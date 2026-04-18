package scan

// headerremoval.go — Header removal / Keep-Alive header stripping detection
//
// Maps to HeaderRemovalScan.java.
//
// Some reverse proxies strip the Host header (or other critical headers)
// based on Connection: keep-alive combined with a Keep-Alive header listing
// headers to remove. If the proxy strips the real Host header but the back-end
// still receives the request (possibly with an injected Host in the body),
// arbitrary header injection becomes possible.
//
// Detection strategy:
//   1. Build a POST with body = "Host: <canary>" and CL = len(body).
//   2. Send with Keep-Alive: timeout=5, max=1000 (attack variant).
//   3. Send without Keep-Alive (harmless control).
//   4. If status or body differs (specifically, if canary appears in attack
//      but not in harmless), report.
//   5. Repeat 5 times for stability; filter round-robin noise with a
//      final out-of-order check.

import (
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"fmt"
	"net/url"
	"strings"

	"github.com/smuggled/smuggled/internal/report"
)

// headerStripTarget defines one hop-by-hop stripping probe.
type headerStripTarget struct {
	strip   string // header name to list in Connection (gets stripped by proxy)
	body    string // request body to send
	canary  string // string to look for in the response (may appear if backend processes the body)
	typeTag string // finding Type label
	desc    string // human-readable description of the attack surface
}

// ScanHeaderRemoval probes for proxy header-stripping via Keep-Alive abuse.
//
// Variants tested:
//
//   - host: proxy strips the Host header → injected Host in body may be used by backend.
//
//   - content-length: proxy strips Content-Length → backend has no CL and no TE.
//     RFC 7230 requires CL or TE for a request with a body; without either the backend
//     may default to CL=0 (leaving the body as a new request — a CL.0 variant), return
//     411 Length Required, or hang. All of these represent a desync-relevant anomaly.
func ScanHeaderRemoval(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	dbg(cfg, "HeaderRemoval: starting, target=%s", target.Host)
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// canaryHost is used as the injected Host value so that if the back-end
	// processes the injected header it will reflect a recognisable domain in
	// error messages (e.g. "Invalid Host: example.com.x00.day").
	canaryHost := target.Hostname() + ".x00.day"

	stripTargets := []headerStripTarget{
		{
			strip:   "host",
			body:    "Host: " + canaryHost,
			canary:  canaryHost,
			typeTag: "header-removal",
			desc: "Proxy strips the Host header listed in Connection hop-by-hop, " +
				"enabling Host header injection via the request body.",
		},
		{
			// Stripping Content-Length leaves the backend with a body and no length signal.
			// Back-ends that default to CL=0 will treat the body as the next pipelined
			// request — a CL.0 desync variant triggered purely by header removal.
			// Back-ends that return 411 or 400 signal anomalous behaviour worth confirming.
			strip:   "content-length",
			body:    "Host: " + canaryHost,
			canary:  canaryHost,
			typeTag: "header-removal-cl",
			desc: "Proxy strips Content-Length listed in Connection hop-by-hop. " +
				"Backend receives a POST with body but without CL or TE — may default to " +
				"CL=0, creating a CL.0-style desync, or return 411/400.",
		},
	}

	for _, st := range stripTargets {
		runHeaderStripProbe(target, path, host, st, cfg, rep)
	}
}

// runHeaderStripProbe executes one header-stripping probe and reports if a signal is found.
func runHeaderStripProbe(target *url.URL, path, host string, st headerStripTarget, cfg config.Config, rep *report.Reporter) {
	attack := buildHeaderRemovalReqFor(path, host, st.body, st.strip, true)
	harmless := buildHeaderRemovalReqFor(path, host, st.body, st.strip, false)

	harmlessResp, _, _, harmlessErr := request.RawRequest(target, harmless, cfg)
	if harmlessErr != nil {
		return
	}
	attackResp, _, _, attackErr := request.RawRequest(target, attack, cfg)
	if attackErr != nil {
		return
	}

	dbg(cfg, "HeaderRemoval[%s]: harmless_status=%d attack_status=%d canary_in_attack=%v canary_in_harmless=%v",
		st.strip,
		request.StatusCode(harmlessResp), request.StatusCode(attackResp),
		request.ContainsStr(attackResp, st.canary),
		request.ContainsStr(harmlessResp, st.canary))

	if isRateLimited(request.StatusCode(attackResp)) || isRateLimited(request.StatusCode(harmlessResp)) {
		dbg(cfg, "HeaderRemoval[%s]: rate-limited response, skipping", st.strip)
		return
	}

	if request.StatusCode(attackResp) == request.StatusCode(harmlessResp) &&
		request.ContainsStr(attackResp, st.canary) == request.ContainsStr(harmlessResp, st.canary) {
		return
	}

	// Confirm stability across 5 attempts
	diffCount := 0
	for i := 0; i < 5; i++ {
		hr, _, _, e1 := request.RawRequest(target, harmless, cfg)
		ar, _, _, e2 := request.RawRequest(target, attack, cfg)
		if e1 != nil || e2 != nil {
			continue
		}
		if isRateLimited(request.StatusCode(ar)) || isRateLimited(request.StatusCode(hr)) {
			continue
		}
		if request.StatusCode(ar) != request.StatusCode(hr) ||
			request.ContainsStr(ar, st.canary) != request.ContainsStr(hr, st.canary) {
			diffCount++
		}
	}
	dbg(cfg, "HeaderRemoval[%s]: stability diffCount=%d/5", st.strip, diffCount)
	if diffCount < 3 {
		return
	}

	// Final out-of-order check to filter round-robin noise
	finalAtk, _, _, _ := request.RawRequest(target, attack, cfg)
	if request.StatusCode(finalAtk) == request.StatusCode(harmlessResp) &&
		request.ContainsStr(finalAtk, st.canary) == request.ContainsStr(harmlessResp, st.canary) {
		return
	}

	rep.Emit(report.Finding{
		Target:    target.String(),
		Method:    config.EffectiveMethods(cfg)[0],
		Severity:  report.SeverityProbable,
		Type:      st.typeTag,
		Technique: "Keep-Alive-" + st.strip + "-stripping",
		Description: fmt.Sprintf(
			"%s Response divergence: attack status=%d harmless status=%d "+
				"(canary-in-attack=%v canary-in-harmless=%v).",
			st.desc,
			request.StatusCode(attackResp), request.StatusCode(harmlessResp),
			request.ContainsStr(attackResp, st.canary),
			request.ContainsStr(harmlessResp, st.canary)),
		Evidence: fmt.Sprintf(
			"strip=%s attack_status=%d harmless_status=%d canary=%s",
			st.strip, request.StatusCode(attackResp), request.StatusCode(harmlessResp), st.canary),
		RawProbe: request.Truncate(string(attack), 512),
	})
	rep.Log("HeaderRemoval [!] strip=%s confirmed on %s", st.strip, target.String())
}

// buildHeaderRemovalReqFor builds an attack or harmless request for a given strip target.
//
// attack=true: lists `strip` header in Connection → proxy strips it before forwarding.
// attack=false: uses Eat-Alive instead of Keep-Alive so no stripping occurs (control).
func buildHeaderRemovalReqFor(path, host, body, strip string, attack bool) []byte {
	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	if attack {
		// List the target header as hop-by-hop so the proxy strips it.
		b.WriteString("Connection: keep-alive, " + strip + "\r\n")
		b.WriteString("Keep-Alive: timeout=5, max=1000\r\n")
	} else {
		// Control: same structure but Connection lists nothing harmful.
		b.WriteString("Connection: keep-alive\r\n")
		b.WriteString("Eat-Alive: timeout=5, max=1000\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
