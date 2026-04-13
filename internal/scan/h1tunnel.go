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
	dbg(cfg, "H1Tunnel: starting, target=%s", target.Host)
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	const trigger = "FOO BAR AAH\r\n\r\n"

	// Curated TE technique subset for tunnel probing.
	// We use a broader set than the original 3 (vanilla, nameprefix1, dualchunk)
	// because tunnel detection is cheap (single request per technique) and these
	// techniques cover the most common proxy/backend parser discrepancy surfaces.
	h1TunnelTESubset := []string{
		"vanilla",      // baseline — standard TE: chunked
		"nameprefix1",  // Foo: bar\r\n Transfer-Encoding: chunked (continuation prefix)
		"dualchunk",    // TE: chunked + TE: identity (dual-header, front takes identity)
		"revdualchunk", // TE: identity + TE: chunked (inverse order)
		"tabprefix2",   // Transfer-Encoding\t:\tchunked (tab before and after colon)
		"TE-leadspace", // " Transfer-Encoding: chunked" (leading space on header name)
		"spjunk",       // Transfer-Encoding x: chunked (space-junk in header name)
		"backslash",    // Transfer\Encoding: chunked (backslash in name)
		"contentEnc",   // Content-Encoding: chunked (aliased header name)
		"connection",   // Connection: Transfer-Encoding\r\nTE: chunked
		"nospace1",     // Transfer-Encoding:chunked (no space after colon)
		"space1",       // Transfer-Encoding : chunked (space before colon)
	}

	for _, method := range h1TunnelMethods {
		req := buildH1TunnelBase(method, path, host)
		for _, tech := range h1TunnelTESubset {
			// Apply a TE permutation to maximise coverage
			mutated := applyTEOrSkip(req, tech)
			if mutated == nil {
				continue
			}

			// Build the CL.TE attack with the trigger as smuggled body
			attack := buildH1TunnelAttack(mutated, trigger, true)

			rep.Log("H1Tunnel probe: method=%s tech=%s target=%s", method, tech, host)
			dbg(cfg, "H1Tunnel [%s/%s]: CL.TE probe", method, tech)

			resp, elapsed, to, err := request.RawRequest(target, attack, cfg)
			if err != nil {
				continue
			}

			dbg(cfg, "H1Tunnel [%s/%s]: CL.TE → timeout=%v nested=%v status=%d elapsed=%v",
				method, tech, to, !to && len(resp) > 0 && hasNestedHTTPResponse(resp), request.StatusCode(resp), elapsed)
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
				if cfg.ExitOnFind {
					return
				}
				continue
			}

			// TE.CL variant: front-end (TE) stops at 0\r\n\r\n, does not forward 'X'.
			// Back-end (CL=14) expects 14 bytes but receives only 13 → TIMEOUT.
			// Detection is timeout-based (same mechanism as tecl.go, but here the outer
			// request uses a passthrough method + method-override headers).
			attackTE := buildH1TunnelAttack(mutated, trigger, false)
			dbg(cfg, "H1Tunnel [%s/%s]: TE.CL probe", method, tech)
			_, elapsedTE, toTE, errTE := request.RawRequest(target, attackTE, cfg)
			if errTE != nil {
				continue
			}
			delayedTE := cfg.IsDelayed(elapsedTE)
			dbg(cfg, "H1Tunnel [%s/%s]: TE.CL → timeout=%v delayed=%v elapsed=%v", method, tech, toTE, delayedTE, elapsedTE)
			if toTE || delayedTE {
				confirmed := request.ConfirmProbe(target, attackTE, cfg, rep.Log, "H1Tunnel/TE.CL")
				sev := report.SeverityProbable
				if confirmed {
					sev = report.SeverityConfirmed
				}
				rep.Emit(report.Finding{
					Target:    target.String(),
					Method:    config.EffectiveMethods(cfg)[0],
					Severity:  sev,
					Type:      "H1-tunnel",
					Technique: fmt.Sprintf("%s/%s/TE.CL", method, tech),
					Description: fmt.Sprintf(
						"H1 tunnel desync (TE.CL variant): timeout indicates back-end is waiting "+
							"for a byte the front-end never forwarded (method=%s, technique=%s). "+
							"The outer request uses a passthrough method with method-override headers.",
						method, tech),
					Evidence:  fmt.Sprintf("elapsed=%v confirmed=%v", elapsedTE, confirmed),
					RawProbe:  request.Truncate(string(attackTE), 512),
				})
				if cfg.ExitOnFind {
					return
				}
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
//
// CL.TE (mirrors getCLTEAttack in Java):
//   body = "3\r\nx=y\r\n0\r\n\r\n" + trigger
//   CL   = len(body)  — full body length, no truncation
//   The back-end (TE) reads the chunked body, hits 0\r\n\r\n, then sees trigger
//   as extra bytes after the terminator → processes trigger as a nested request.
//
// TE.CL (mirrors getTECLAttack in Java):
//   body = trigger + "3\r\nx=y\r\n0\r\n\r\n"  (trigger prepended to chunked body)
//   CL   = index of trigger in body = 0  (CL points just before the trigger)
//   Actually Java wraps all of it in chunked encoding with CL = offset of trigger.
//   Simpler Go equivalent: body = "3\r\nx=y\r\n0\r\n\r\n", CL = len(body)+1, append X
//   — reuse the same TE.CL probe approach so back-end (CL) waits for 1 extra byte.
func buildH1TunnelAttack(base []byte, trigger string, clte bool) []byte {
	if clte {
		// CL.TE: full chunked body + trigger appended after terminator.
		// CL = exact full body length so front-end (CL) forwards everything.
		// Back-end (TE) terminates at 0\r\n\r\n then sees trigger as tunnelled content.
		body := "3\r\nx=y\r\n0\r\n\r\n" + trigger
		return request.SetContentLength(request.SetBody(base, body), len(body))
	}
	// TE.CL: body = exact chunked body, CL = bodyLen+1, X appended after request.
	// Front-end (TE) forwards body up to 0\r\n\r\n (13 bytes); back-end (CL=14)
	// waits for 1 more byte → TIMEOUT.
	const teClBody = "3\r\nx=y\r\n0\r\n\r\n"
	req := request.SetContentLength(request.SetBody(base, teClBody), len(teClBody)+1)
	req = append(req, 'X')
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
