package scan

// cl0.go — CL.0 (Content-Length: 0) desync detection
//
// Three detection strategies:
//
//   1. Gadget bleed (CONFIRMED): marker from the smuggled request leaks into
//      a subsequent response — proves the backend treated the body as a new request.
//
//   2. Status divergence (PROBABLE): the probe response status differs from the
//      baseline after the smuggle — the smuggled prefix altered backend routing.
//      Adapted from CLZero (github.com/Moopinger/CLZero).
//
//   3. Status 400 potential: CL mutation causes 400 where baseline was 2xx,
//      only when body is present — the server may be parsing body as a new request.
//
// Connection modes (in order of speed):
//
//   - Last-byte-sync: open probe connection first, send all but last byte;
//     send full smuggle on second connection; fire last byte of probe.
//     Maximizes chance of catching the poisoned backend connection.
//
//   - Skip-read: send smuggle without reading response, immediately send probe.
//     Faster than sequential, good for most targets.
//
//   - Sequential (fallback): send smuggle, read response, send probe.

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/permute"
	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/request"
)

// cl0Gadget represents a candidate smuggled inner-request used to confirm CL.0.
// The gadget is fired directly to verify it produces a distinctive response,
// then used as the smuggled body in the attack. If the probe response reflects
// the gadget marker, the backend demonstrably processed the smuggled request.
type cl0Gadget struct {
	payload    string // request-line to inject as smuggled prefix
	lookFor    string // marker to search for in the follow-up probe response
	headerOnly bool   // true = only search in response headers, not body
}

// clGadgets are the static candidate inner-requests for CL.0 gadget detection,
// listed in priority order (most distinctive / cheapest first).
// A dynamic canary-path gadget is prepended at runtime in selectCL0Gadget.
var clGadgets = []cl0Gadget{
	{"GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1", "wrtztrw", false},
	{"GET /robots.txt HTTP/1.1", "llow:", false},
	{"GET /favicon.ico HTTP/1.1", "image/", true},
	// "405 " (trailing space) avoids false positives from UUIDs/IDs containing
	// "405" as a substring (e.g. x-request-id: ...-9405-...).
	{"TRACE / HTTP/1.1", "405 ", true},
	{"GET / HTTP/2.2", "505 ", true},
}

// cl0TraceGadget is the TRACE fallback used when no other gadget is viable.
// Defined separately so ScanCL0 and ScanH2CL0 can reference it by name
// rather than by index (index 3 = TRACE in the static list above).
var cl0TraceGadget = &clGadgets[3]

// clMutation is a single Content-Length obfuscation technique.
type clMutation struct {
	name   string
	mutate func(req []byte, clVal string) []byte
}

// allCLMutations returns the complete list of CL.0 mutation techniques:
//   - 12 existing techniques (CL-plus, CL-minus, CL-pad, etc.)
//   - 4 CLZero-derived static techniques (CL-alpha, CL-subtract, CL-under, CL-smashed)
//   - 130 CLZero dynamic byte-family techniques (10 families × 13 byte values)
//
// Total: ~146 techniques per scan.
func allCLMutations() []clMutation {
	// Helper: wrap ApplyCL call into a closure capturing the technique name.
	cl := func(name string) clMutation {
		return clMutation{name, func(r []byte, v string) []byte {
			return permute.ApplyCL(r, name, v)
		}}
	}

	out := []clMutation{
		// ── Existing techniques ───────────────────────────────────────────────
		cl("CL-plus"),
		cl("CL-minus"),
		cl("CL-pad"),
		cl("CL-bigpad"),
		cl("CL-e"),
		cl("CL-dec"),
		cl("CL-commaprefix"),
		cl("CL-commasuffix"),
		cl("CL-error"),
		cl("CL-spacepad"),
		cl("CL-expect"),
		cl("CL-expect-obfs"),

		// ── Dual CL header attacks ────────────────────────────────────────────
		// Two Content-Length headers with conflicting values — RFC 7230 §3.3.2 says
		// reject; proxies and back-ends disagree on which one wins.
		cl("CL-dual-zero-first"), // CL: 0\r\nCL: <n> — front takes first, back takes last
		cl("CL-dual-zero-last"),  // CL: <n>\r\nCL: 0 — front takes last, back takes first

		// ── CLZero-derived static techniques ─────────────────────────────────
		// Source: github.com/Moopinger/CLZero/blob/main/configs/default.py
		cl("CL-alpha"),    // Content-Length: <n>aa ("normalize" in CLZero)
		cl("CL-subtract"), // Content-Length: <n>-0 ("subtract" in CLZero)
		cl("CL-under"),    // Content_Length: <n>   ("underjoin1" in CLZero)
		cl("CL-smashed"),  // Content Length:<n>    ("smashed" in CLZero)
	}

	// ── CLZero dynamic byte-family techniques ─────────────────────────────────
	// 10 position families × 13 byte values = 130 permutations.
	clFamilies := []string{
		"CL-midspace",   // Content-Length:<byte><value>
		"CL-postspace",  // Content-Length<byte>: <value>
		"CL-prespace",   // <byte>Content-Length: <value>
		"CL-endspace",   // Content-Length: <value><byte>
		"CL-xprespace",  // X: X<byte>Content-Length: <value>
		"CL-endspacex",  // Content-Length: <value><byte>X: X
		"CL-rxprespace", // X: X\r<byte>Content-Length: <value>
		"CL-xnprespace", // X: X<byte>\nContent-Length: <value>
		"CL-endspacerx", // Content-Length: <value>\r<byte>X: X
		"CL-endspacexn", // Content-Length: <value><byte>\nX: X
	}
	for _, b := range permute.CLZeroBytes() {
		sfx := fmt.Sprintf("-%02x", b)
		for _, fam := range clFamilies {
			out = append(out, cl(fam+sfx))
		}
	}

	return out
}

// ScanCL0 runs CL.0 desync detection with all CL mutation techniques.
func ScanCL0(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("CL0")
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	dbg(cfg, "starting, target=%s path=%s", host, path)

	method := config.EffectiveMethod(cfg, true)
	basePost := request.BuildKeepAliveRequest(method, path, host)

	// Establish baseline status for status-divergence detection
	baseResp, _, _, _ := request.RawRequest(target, basePost, cfg)
	baseStatus := request.StatusCode(baseResp)
	dbg(cfg, "baseline status=%d", baseStatus)

	// Build a clean probe request (Connection: close GET to same path)
	probeReq := request.BuildGETRequest("GET "+path+" HTTP/1.1", host)

	// Detect which gadget is viable
	gadget := selectCL0Gadget(target, basePost, cfg, rep)
	if gadget == nil {
		dbg(cfg, "no viable gadget found, using TRACE fallback")
		rep.Log("CL.0: no viable gadget found for %s, using TRACE fallback", host)
		gadget = cl0TraceGadget
	} else {
		dbg(cfg, "selected gadget payload=%q marker=%q", gadget.payload, gadget.lookFor)
	}

	canary := "YzBqvXxSmuggled"
	smuggledPrefix := fmt.Sprintf("%s\r\nX-%s: ", gadget.payload, canary)

	for _, mut := range allCLMutations() {
		if !techniqueEnabled(mut.name, cfg) {
			continue
		}
		dbg(cfg, "[%s]: starting, gadget=%q", mut.name, gadget.payload)
		rep.Log("CL.0 probe: technique=%s gadget=%s target=%s", mut.name, gadget.payload, host)

		// Build attack: body = smuggled prefix, CL mutated to look like 0
		clVal := fmt.Sprintf("%d", len(smuggledPrefix))
		attackReq := request.SetBody(basePost, smuggledPrefix)
		attackReq = request.SetContentLength(attackReq, len(smuggledPrefix))
		attackReq = mut.mutate(attackReq, clVal)

		for i := 0; i < cfg.Attempts; i++ {
			// ── Phase 1: Try last-byte-sync (best precision) ─────────
			probeResp, _, probeTimeout, probeErr := request.LastByteSyncProbe(
				target, attackReq, probeReq, cfg)

			if probeErr != nil || probeTimeout {
				dbg(cfg, "[%s]: last-byte-sync attempt %d err=%v timeout=%v, trying skip-read",
					mut.name, i, probeErr, probeTimeout)

				// ── Phase 2: Fallback to skip-read ───────────────────
				if err := request.SendNoRecv(target, attackReq, cfg); err != nil {
					dbg(cfg, "[%s]: skip-read send error: %v", mut.name, err)
					break
				}
				probeResp, _, probeTimeout, probeErr = request.RawRequest(target, probeReq, cfg)
				if probeErr != nil || probeTimeout {
					dbg(cfg, "[%s]: skip-read probe failed: err=%v timeout=%v", mut.name, i, probeErr, probeTimeout)
					break
				}
			}

			probeStatus := request.StatusCode(probeResp)
			dbg(cfg, "[%s]: attempt %d probeStatus=%d probeLen=%d",
				mut.name, i, probeStatus, len(probeResp))

			// ── Detection 1: Gadget bleed (CONFIRMED) ────────────────
			if gadgetMatches(probeResp, gadget) {
				dbg(cfg, "[%s]: CONFIRMED gadget bleed at attempt %d", mut.name, i)
				rep.Emit(report.Finding{
					Target:   target.String(),
					Method:   config.EffectiveMethods(cfg)[0],
					Severity: report.SeverityConfirmed,
					Type:     "CL.0",
					Technique: mut.name + "|" + gadget.payload,
					Description: fmt.Sprintf(
						"CL.0 desync confirmed: after %d attempts with technique '%s', "+
							"response reflected gadget marker '%s' from smuggled prefix.",
						i, mut.name, gadget.lookFor),
					Evidence: fmt.Sprintf("attempt=%d smuggled_prefix=%q probe_status=%d", i, smuggledPrefix, probeStatus),
					RawProbe: request.Truncate(string(attackReq), 512),
				})
				if cfg.ExitOnFind {
					return
				}
				break // found for this mutation — move to next
			}

			// ── Detection 2: Status divergence (PROBABLE) ────────────
			if i > 0 && baseStatus > 0 && probeStatus > 0 &&
				probeStatus != baseStatus && probeStatus != 429 {
				dbg(cfg, "[%s]: status divergence at attempt %d: base=%d probe=%d",
					mut.name, i, baseStatus, probeStatus)
				rep.Emit(report.Finding{
					Target:   target.String(),
					Method:   config.EffectiveMethods(cfg)[0],
					Severity: report.SeverityProbable,
					Type:     "CL.0-divergence",
					Technique: mut.name,
					Description: fmt.Sprintf(
						"CL.0 status divergence: technique '%s' caused probe status %d "+
							"(baseline: %d) after %d smuggle attempts. The smuggled prefix "+
							"may have altered backend routing.",
						mut.name, probeStatus, baseStatus, i),
					Evidence: fmt.Sprintf("baseline=%d probe=%d attempt=%d", baseStatus, probeStatus, i),
					RawProbe: request.Truncate(string(attackReq), 512),
				})
				if cfg.ExitOnFind {
					return
				}
				break // found for this mutation — move to next
			}

			// ── Detection 3: Status 400 potential ────────────────────
			if i > 0 && baseStatus > 0 && baseStatus < 400 && probeStatus == 400 {
				// Verify: mutation with harmless body should NOT cause 400
				fakeReq := request.SetBody(basePost, " ")
				fakeReq = request.SetContentLength(fakeReq, 1)
				fakeReq = mut.mutate(fakeReq, "1")
				allGood := true
				for k := 0; k < 5; k++ {
					fr, _, _, ferr := request.RawRequest(target, fakeReq, cfg)
					if ferr != nil || request.StatusCode(fr) == 400 {
						allGood = false
						break
					}
				}
				if allGood {
					rep.Emit(report.Finding{
						Target:   target.String(),
						Method:   config.EffectiveMethods(cfg)[0],
						Severity: report.SeverityProbable,
						Type:     "CL.0-potential",
						Technique: mut.name,
						Description: fmt.Sprintf(
							"Potential CL.0: technique '%s' caused status 400 (baseline: %d) "+
								"only when smuggled body is present.",
							mut.name, baseStatus),
						Evidence: fmt.Sprintf("baseline=%d probe=400 attempt=%d", baseStatus, i),
					})
					if cfg.ExitOnFind {
						return
					}
				}
			}
		}
	}
}

// ScanH2CL0 is the HTTP/2 variant of ScanCL0, delivering the same CL.0 attack
// via H2→H1 downgrade using forbidden or malformed headers (matches Burp Suite scanner).
//
// Mechanism:
//   - "Connection: keep-alive" is a hop-by-hop header forbidden in HTTP/2 (RFC 7540 §8.1.2.2).
//     Some front-ends forward it verbatim during H2→H1 downgrade.
//   - "Expect: x 100-continue" is malformed. Some H1 back-ends treat the request as
//     body-less when Expect is unrecognised, leaving the DATA frame bytes in the TCP buffer.
//   - Those buffered bytes are then parsed as the first line of the next H1 request (CL.0).
//
// Detection: same gadget-bleed strategy as ScanCL0 — use selectCL0Gadget to find a
// viable gadget, send the attack with the gadget as body, probe with a clean H2 GET,
// and check if the probe response reflects the gadget marker or diverges in status.
func ScanH2CL0(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("H2CL0")
	if target.Scheme != "https" {
		return
	}
	if !request.ProbeH2(target, cfg) {
		rep.Log("H2CL0: %s does not negotiate h2, skipping", target.Host)
		return
	}

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// Reuse the same H1 gadget selection: test each candidate path directly
	// to find one whose response is distinctive and not present in baseline.
	baseReq := request.BuildKeepAliveRequest("GET", path, host)
	gadget := selectCL0Gadget(target, baseReq, cfg, rep)
	if gadget == nil {
		dbg(cfg, "H2CL0: no viable gadget found, using TRACE fallback")
		rep.Log("H2CL0: no viable gadget found for %s, using TRACE fallback", host)
		gadget = cl0TraceGadget
	} else {
		dbg(cfg, "H2CL0: selected gadget payload=%q marker=%q", gadget.payload, gadget.lookFor)
	}

	// smuggledBody = incomplete H1 request prefix; the absorber header (X-YzBqv:)
	// swallows the first line of the real next request, completing the injection cleanly.
	smuggledBody := fmt.Sprintf("%s\r\nX-YzBqv: ", gadget.payload)

	// Baseline via H2 to detect status divergence
	baseline, err := h2RawRequest(target, "GET", path, host, "", nil, cfg)
	if err != nil || baseline.Status == 0 {
		dbg(cfg, "H2CL0: baseline failed: %v", err)
		return
	}
	baseStatus := baseline.Status
	dbg(cfg, "H2CL0: baseline status=%d gadget=%q", baseStatus, gadget.payload)

	// Header permutations — each isolates a specific forbidden/malformed trigger.
	// Mirrors the exact headers observed in Burp Suite's CL.0 H2 scanner.
	// Each technique is tested twice:
	//   - no-cl variant: content-length suppressed (sentinel ""). The backend must
	//     infer body absence from the malformed Expect/Connection headers alone.
	//   - cl variant: content-length present (normal len(body)). Some front-ends
	//     only trigger CL.0 when CL is explicit; others are blocked by it.
	headerPerms := []struct {
		name  string
		extra map[string]string
	}{
		{
			"connection+expect-obfs/no-cl",
			map[string]string{
				"connection":     "keep-alive",
				"expect":         "x 100-continue",
				"content-length": "",
			},
		},
		{
			"connection+expect-obfs/cl",
			map[string]string{
				"connection": "keep-alive",
				"expect":     "x 100-continue",
			},
		},
		{
			"connection-only/no-cl",
			map[string]string{
				"connection":     "keep-alive",
				"content-length": "",
			},
		},
		{
			"connection-only/cl",
			map[string]string{
				"connection": "keep-alive",
			},
		},
		{
			"expect-obfs-only/no-cl",
			map[string]string{
				"expect":         "x 100-continue",
				"content-length": "",
			},
		},
		{
			"expect-obfs-only/cl",
			map[string]string{
				"expect": "x 100-continue",
			},
		},
		{
			"expect-standard/no-cl",
			map[string]string{
				"expect":         "100-continue",
				"content-length": "",
			},
		},
		{
			"expect-standard/cl",
			map[string]string{
				"expect": "100-continue",
			},
		},
	}

	for _, method := range config.EffectiveMethods(cfg) {
		for _, perm := range headerPerms {
			if !techniqueEnabled("H2.CL0/"+perm.name, cfg) {
				continue
			}
			rep.Log("H2CL0 probe: method=%s perm=%s gadget=%s target=%s",
				method, perm.name, gadget.payload, host)
			dbg(cfg, "H2CL0 [%s/%s]: smuggled=%q", method, perm.name, smuggledBody)

			for attempt := 0; attempt < cfg.Attempts; attempt++ {
				// Single-connection probe: attack on stream 1, probe GET on stream 3.
				// Both streams share the same H2→back-end TCP connection, so the probe
				// lands on the same back-end worker that received the poisoned buffer.
				_, probe, err := h2AttackAndProbe(
					target, method, path, host, smuggledBody, perm.extra, cfg)
				if err != nil {
					dbg(cfg, "H2CL0 [%s/%s]: attempt %d error: %v",
						method, perm.name, attempt, err)
					continue
				}
				if probe.Status == 0 {
					dbg(cfg, "H2CL0 [%s/%s]: attempt %d probe status=0, skipping",
						method, perm.name, attempt)
					continue
				}

				probeStatus := probe.Status
				// For headerOnly gadgets check decoded headers; otherwise check body.
				var probeBytes []byte
				if gadget.headerOnly {
					for _, hf := range probe.Headers {
						probeBytes = append(probeBytes, []byte(hf.Name+": "+hf.Value+"\r\n")...)
					}
				} else {
					probeBytes = probe.Body
				}
				gadgetFound := request.ContainsStr(probeBytes, gadget.lookFor)

				dbg(cfg, "H2CL0 [%s/%s]: attempt %d probeStatus=%d baseline=%d gadget=%v",
					method, perm.name, attempt, probeStatus, baseStatus, gadgetFound)

				// ── Detection 1: gadget marker reflected (CONFIRMED) ─────
				if gadgetFound {
					dbg(cfg, "H2CL0 [%s/%s]: CONFIRMED gadget bleed at attempt %d",
						method, perm.name, attempt)
					rep.Emit(report.Finding{
						Target:    target.String(),
						Method:    "HTTP/2",
						Severity:  report.SeverityConfirmed,
						Type:      "H2.CL0",
						Technique: fmt.Sprintf("H2.CL0/%s/%s", method, perm.name),
						Description: fmt.Sprintf(
							"H2 CL.0 desync confirmed (single-connection): forbidden/malformed "+
								"headers (%s) caused the H2→H1 downgrade to leave the DATA body "+
								"in the TCP buffer. Back-end parsed it as a new request; "+
								"probe on stream 3 reflected gadget marker '%s' from '%s' "+
								"(method=%s, attempt=%d).",
							perm.name, gadget.lookFor, gadget.payload, method, attempt),
						Evidence: fmt.Sprintf("attempt=%d gadget=%q marker=%q probe_status=%d baseline=%d",
							attempt, gadget.payload, gadget.lookFor, probeStatus, baseStatus),
						RawProbe: fmt.Sprintf(
							"[stream 1] %s %s HTTP/2\r\nHost: %s\r\n%v\r\ncontent-length: %d\r\n\r\n%s\n"+
								"[stream 3] GET %s HTTP/2\r\nHost: %s\r\n",
							method, path, host, perm.extra, len(smuggledBody), smuggledBody, path, host),
					})
					if cfg.ExitOnFind {
						return
					}
					break
				}

				// ── Detection 2: status divergence (PROBABLE) ────────────
				if attempt > 0 && probeStatus != baseStatus && probeStatus != 429 {
					dbg(cfg, "H2CL0 [%s/%s]: status divergence at attempt %d: base=%d probe=%d",
						method, perm.name, attempt, baseStatus, probeStatus)
					rep.Emit(report.Finding{
						Target:    target.String(),
						Method:    "HTTP/2",
						Severity:  report.SeverityProbable,
						Type:      "H2.CL0",
						Technique: fmt.Sprintf("H2.CL0/%s/%s", method, perm.name),
						Description: fmt.Sprintf(
							"H2 CL.0 desync (single-connection): probe on stream 3 returned "+
								"status %d vs baseline %d after %d attempts "+
								"(headers=%s, method=%s). The smuggled prefix may have "+
								"altered back-end routing on the shared connection.",
							probeStatus, baseStatus, attempt, perm.name, method),
						Evidence: fmt.Sprintf("attempt=%d probe_status=%d baseline=%d",
							attempt, probeStatus, baseStatus),
						RawProbe: fmt.Sprintf(
							"[stream 1] %s %s HTTP/2\r\nHost: %s\r\n%v\r\ncontent-length: %d\r\n\r\n%s\n"+
								"[stream 3] GET %s HTTP/2\r\nHost: %s\r\n",
							method, path, host, perm.extra, len(smuggledBody), smuggledBody, path, host),
					})
					if cfg.ExitOnFind {
						return
					}
					break
				}
			}
		}
	}
}

// selectCL0Gadget fires each gadget request directly to find one whose
// response is distinctive and not already present in baseline responses.
//
// The canary path (cfg.CanaryPath) is prepended as a high-priority dynamic
// gadget: many servers echo the requested path in 404 error pages, making
// the canary string a reliable and unique marker.
func selectCL0Gadget(target *url.URL, baseReq []byte, cfg config.Config, rep *report.Reporter) *cl0Gadget {
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}

	// Build the dynamic canary gadget. The marker is the path without the leading "/"
	// so it matches "smuggled-canary-xzyw" even when surrounded by other characters
	// (e.g. in "<a href="/smuggled-canary-xzyw">Not Found</a>").
	canaryPath := cfg.CanaryPath
	if canaryPath == "" {
		canaryPath = "/smuggled-canary-xzyw"
	}
	canaryMarker := strings.TrimPrefix(canaryPath, "/")
	canaryGadget := cl0Gadget{
		payload:    "GET " + canaryPath + " HTTP/1.1",
		lookFor:    canaryMarker,
		headerOnly: false,
	}

	// Candidates: canary gadget first (most distinctive), then static list.
	candidates := append([]cl0Gadget{canaryGadget}, clGadgets...)

	baseResp, _, _, _ := request.RawRequest(target, baseReq, cfg)

	for i := range candidates {
		g := &candidates[i]
		basePath := target.RequestURI()
		if basePath == "" {
			basePath = "/"
		}
		if strings.Contains(g.payload, basePath+" ") && basePath != "/" {
			continue
		}
		gadgetReq := request.BuildGETRequest(g.payload, host)
		resp, _, timedOut, err := request.RawRequest(target, gadgetReq, cfg)
		if err != nil || timedOut || len(resp) == 0 {
			continue
		}
		if baseResp != nil && request.ContainsStr(baseResp, g.lookFor) {
			continue
		}
		if !gadgetMatches(resp, g) {
			continue
		}
		rep.Log("CL.0: selected gadget '%s' (marker=%q) for %s", g.payload, g.lookFor, host)
		return g
	}
	return nil
}

// gadgetMatches checks whether resp contains the gadget's marker string.
func gadgetMatches(resp []byte, g *cl0Gadget) bool {
	if g.headerOnly {
		end := len(resp)
		for i := 0; i < len(resp)-3; i++ {
			if resp[i] == '\r' && resp[i+1] == '\n' && resp[i+2] == '\r' && resp[i+3] == '\n' {
				end = i
				break
			}
		}
		return request.ContainsStr(resp[:end], g.lookFor)
	}
	return request.ContainsStr(resp, g.lookFor)
}
