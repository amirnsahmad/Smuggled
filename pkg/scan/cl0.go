package scan

// cl0.go — CL.0 (Content-Length: 0) desync detection
//
// Maps to ImplicitZeroScan.java.
//
// CL.0 works by sending a request with an obfuscated Content-Length: 0
// (or a CL mutation that some servers interpret as 0) while the body
// contains a smuggled HTTP/1.1 request prefix. The back-end, reading
// CL=0, considers the request body-less and passes the remaining bytes
// (the smuggled prefix) as the start of the next request.
//
// Detection strategy:
//   1. Select a "gadget" — a request path whose response is distinctive
//      (e.g. /robots.txt → "llow:", TRACE → 405, /wrtztrw → canary echo).
//   2. Craft an attack with CL mutation + smuggled GET to the gadget path.
//   3. Send the attack N times. If after i>0 attempts we see the gadget
//      response bleed into a normal request, CL.0 is confirmed.
//   4. Additionally probe for "potential CL.0": if a CL mutation causes
//      a 400 on a normally-200 endpoint, flag it.
//
// CL mutation techniques applied: CL-plus, CL-minus, CL-pad, CL-bigpad,
// CL-e, CL-dec, CL-commaprefix, CL-commasuffix, CL-error, CL-spacepad.

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/smuggled/smuggled/pkg/permute"
	"github.com/smuggled/smuggled/pkg/report"
)

// clGadgets are candidate paths whose distinctive responses can be used
// to confirm CL.0 — listed in priority order (cheapest detection first).
var clGadgets = []struct {
	payload   string // request-line to inject as smuggled prefix
	lookFor   string // marker to look for in response body
	headerOnly bool   // only search in headers, not body
}{
	{"GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1", "wrtztrw", false},
	{"GET /robots.txt HTTP/1.1", "llow:", false},            // User-agent: / Disallow:
	{"GET /favicon.ico HTTP/1.1", "image/", true},
	{"TRACE / HTTP/1.1", "405", true},
	{"GET / HTTP/2.2", "505", true},                         // invalid HTTP version → 505
}

// clMutations are the Content-Length obfuscation techniques to try.
// Each produces a CL value that some parsers read as 0.
var clMutations = []struct {
	name    string
	mutate  func(req []byte, clVal string) []byte
}{
	{"CL-plus",        func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-plus", v) }},
	{"CL-minus",       func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-minus", v) }},
	{"CL-pad",         func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-pad", v) }},
	{"CL-bigpad",      func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-bigpad", v) }},
	{"CL-e",           func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-e", v) }},
	{"CL-dec",         func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-dec", v) }},
	{"CL-commaprefix", func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-commaprefix", v) }},
	{"CL-commasuffix", func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-commasuffix", v) }},
	{"CL-error",       func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-error", v) }},
	{"CL-spacepad",    func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-spacepad", v) }},
	{"CL-expect",      func(r []byte, v string) []byte { return permute.ApplyCL(r, "CL-expect", v) }},
}

// ScanCL0 runs CL.0 desync detection with all CL mutation techniques.
func ScanCL0(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// Build a clean keep-alive POST base for CL.0 probing
	method := effectiveMethod(cfg, true)
	basePost := buildCL0Base(method, path, host)

	// Detect which gadget is viable for this target
	gadget := selectCL0Gadget(target, basePost, cfg, rep)
	if gadget == nil {
		rep.Log("CL.0: no viable gadget found for %s, using TRACE fallback", host)
		gadget = &clGadgets[3] // TRACE → 405 fallback
	}

	canary := "YzBqvXxSmuggled"
	smuggledPrefix := fmt.Sprintf("%s\r\nX-%s: ", gadget.payload, canary)

	for _, mut := range clMutations {
		if !techniqueEnabled("CL0-"+mut.name, cfg) {
			continue
		}
		rep.Log("CL.0 probe: technique=%s gadget=%s target=%s", mut.name, gadget.payload, host)

		// Build attack: body = smuggled prefix, CL mutated to look like 0
		clVal := fmt.Sprintf("%d", len(smuggledPrefix))
		req := setBody(basePost, smuggledPrefix)
		req = setContentLength(req, len(smuggledPrefix))
		req = mut.mutate(req, clVal)

		baseStatus := 0
		baseResp, _, _, _ := rawRequest(target, basePost, cfg)
		if baseResp != nil {
			baseStatus = statusCode(baseResp)
		}

		// Send the attack up to 9 times; look for gadget bleed after attempt 1
		var lastResp []byte
		for i := 0; i < 9; i++ {
			resp, _, timedOut, err := rawRequest(target, req, cfg)
			if err != nil || timedOut {
				break
			}

			if i > 0 {
				// Check whether previous attack body poisoned this response
				if gadgetMatches(resp, gadget) {
					rep.Emit(report.Finding{
						Target:   target.String(),
						Severity: report.SeverityConfirmed,
						Type:     "CL.0",
						Technique: mut.name + "|" + gadget.payload,
						Description: fmt.Sprintf(
							"CL.0 desync confirmed: after %d attempts with technique '%s', "+
								"response reflected gadget marker '%s' from smuggled prefix. "+
								"Reference: https://portswigger.net/research/browser-powered-desync-attacks",
							i, mut.name, gadget.lookFor),
						Evidence:  fmt.Sprintf("attempt=%d smuggled_prefix=%q", i, smuggledPrefix),
						RawProbe:  truncate(string(req), 512),
					})
					rep.Log("CL.0 [!] confirmed: %s/%s on %s", mut.name, gadget.payload, target.String())
					return
				}

				// Potential CL.0: mutation caused 400 on a normally-2xx endpoint
				if baseStatus > 0 && baseStatus < 400 && statusCode(resp) == 400 {
					// Verify with a space-only body (should NOT trigger 400)
					fakeReq := setBody(basePost, " ")
					fakeReq = setContentLength(fakeReq, 1)
					fakeReq = mut.mutate(fakeReq, "1")
					allGood := true
					for k := 0; k < 5; k++ {
						fr, _, _, ferr := rawRequest(target, fakeReq, cfg)
						if ferr != nil || statusCode(fr) == 400 {
							allGood = false
							break
						}
					}
					if allGood {
						rep.Emit(report.Finding{
							Target:    target.String(),
							Severity:  report.SeverityProbable,
							Type:      "CL.0-potential",
							Technique: mut.name,
							Description: fmt.Sprintf(
								"Potential CL.0: technique '%s' caused status 400 (baseline: %d) "+
									"only when body is present, suggesting the server may be parsing "+
									"the body as a new request. "+
									"Reference: https://portswigger.net/research/http1-must-die",
								mut.name, baseStatus),
							Evidence: fmt.Sprintf("baseline=%d probe=400 attempt=%d", baseStatus, i),
						})
					}
				}
			}
			lastResp = resp
		}
		_ = lastResp
	}
}

// selectCL0Gadget fires each gadget request directly to find one whose
// response is distinctive and not already present in baseline responses.
func selectCL0Gadget(target *url.URL, baseReq []byte, cfg Config, rep *report.Reporter) *struct {
	payload    string
	lookFor    string
	headerOnly bool
} {
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}

	baseResp, _, _, _ := rawRequest(target, baseReq, cfg)

	for i := range clGadgets {
		g := &clGadgets[i]
		basePath := target.RequestURI()
		if basePath == "" {
			basePath = "/"
		}
		// Don't probe the same path we're attacking
		if strings.Contains(g.payload, basePath+" ") && basePath != "/" {
			continue
		}
		// Build a clean GET to the gadget path
		gadgetReq := buildSimpleGET(g.payload, host)
		resp, _, timedOut, err := rawRequest(target, gadgetReq, cfg)
		if err != nil || timedOut || len(resp) == 0 {
			continue
		}
		// Skip if baseline already contains the gadget marker
		if baseResp != nil && containsStr(baseResp, g.lookFor) {
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
func gadgetMatches(resp []byte, g *struct {
	payload    string
	lookFor    string
	headerOnly bool
}) bool {
	if g.headerOnly {
		// Only check up to \r\n\r\n
		end := len(resp)
		for i := 0; i < len(resp)-3; i++ {
			if resp[i] == '\r' && resp[i+1] == '\n' && resp[i+2] == '\r' && resp[i+3] == '\n' {
				end = i
				break
			}
		}
		return containsStr(resp[:end], g.lookFor)
	}
	return containsStr(resp, g.lookFor)
}

func buildCL0Base(method, path, host string) []byte {
	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	b.WriteString("\r\n")
	return []byte(b.String())
}

func buildSimpleGET(requestLine, host string) []byte {
	// requestLine is like "GET /robots.txt HTTP/1.1"
	// we need to convert it to a full request
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return nil
	}
	path := parts[1]
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	return []byte(b.String())
}

func techniqueEnabled(name string, cfg Config) bool {
	if len(cfg.TechniquesFilter) == 0 {
		return true
	}
	for _, t := range cfg.TechniquesFilter {
		if strings.EqualFold(t, name) {
			return true
		}
	}
	return false
}
