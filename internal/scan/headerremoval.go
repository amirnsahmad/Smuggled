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

const headerRemovalCanary = "wrtzwrrrrr"

// ScanHeaderRemoval probes for proxy header-stripping via Keep-Alive abuse.
func ScanHeaderRemoval(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	body := "Host: " + headerRemovalCanary

	// Build attack (with Keep-Alive header) and harmless (without)
	attack := buildHeaderRemovalReq(path, host, body, true)
	harmless := buildHeaderRemovalReq(path, host, body, false)

	harmlessResp, _, _, harmlessErr := request.RawRequest(target, harmless, cfg)
	if harmlessErr != nil {
		return
	}

	attackResp, _, _, attackErr := request.RawRequest(target, attack, cfg)
	if attackErr != nil {
		return
	}

	// If responses are identical, not interesting
	if request.StatusCode(attackResp) == request.StatusCode(harmlessResp) &&
		request.ContainsStr(attackResp, headerRemovalCanary) == request.ContainsStr(harmlessResp, headerRemovalCanary) {
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
		if request.StatusCode(ar) != request.StatusCode(hr) ||
			request.ContainsStr(ar, headerRemovalCanary) != request.ContainsStr(hr, headerRemovalCanary) {
			diffCount++
		}
	}
	if diffCount < 3 {
		return // not stable enough
	}

	// Final out-of-order check to filter round-robin noise
	finalAtk, _, _, _ := request.RawRequest(target, attack, cfg)
	if request.StatusCode(finalAtk) == request.StatusCode(harmlessResp) &&
		request.ContainsStr(finalAtk, headerRemovalCanary) == request.ContainsStr(harmlessResp, headerRemovalCanary) {
		return
	}

	rep.Emit(report.Finding{
		Target:   target.String(),
		Severity: report.SeverityProbable,
		Type:     "header-removal",
		Technique: "Keep-Alive-header-stripping",
		Description: fmt.Sprintf(
			"Header removal vulnerability detected: Keep-Alive header caused different "+
				"response (status %d vs %d, canary-in-attack=%v vs canary-in-harmless=%v). "+
				"The proxy may be stripping headers listed in Keep-Alive, enabling "+
				"Host header injection.",
			request.StatusCode(attackResp), request.StatusCode(harmlessResp),
			request.ContainsStr(attackResp, headerRemovalCanary),
			request.ContainsStr(harmlessResp, headerRemovalCanary)),
		Evidence: fmt.Sprintf(
			"attack_status=%d harmless_status=%d canary=%s",
			request.StatusCode(attackResp), request.StatusCode(harmlessResp), headerRemovalCanary),
		RawProbe: request.Truncate(string(attack), 512),
	})
	rep.Log("HeaderRemoval [!] confirmed on %s", target.String())
}

func buildHeaderRemovalReq(path, host, body string, withKeepAlive bool) []byte {
	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	b.WriteString("Connection: keep-alive\r\n")
	if withKeepAlive {
		b.WriteString("Keep-Alive: timeout=5, max=1000\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}
