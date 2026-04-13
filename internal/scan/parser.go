package scan

// parser.go — Parser Discrepancy detection (v3.0 technique)
//
// Maps to ParserDiscrepancyScan.java + HiddenPair.java + PermutationResult.java
//
// Strategy:
// Send a canary header that a back-end would reject (e.g. Host: foo/bar or CL: Z).
// Then hide that header from the front-end using various obfuscation techniques
// (space, tab, line-wrap, hop-by-hop).
// If the front-end strips the header but the back-end sees it: discrepancy → potential desync.
// Conversely, if the back-end ignores a header the front-end parses: also interesting.

import (
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"github.com/smuggled/smuggled/internal/report"
)

type hideTechnique string

const (
	hideSpace hideTechnique = "space"
	hideTab   hideTechnique = "tab"
	hideWrap  hideTechnique = "wrap"
	hideHop   hideTechnique = "hop"
	hideLpad  hideTechnique = "lpad"
)

type canaryHeader struct {
	name        string
	headerName  string
	value       string
	shouldBlock bool // front-end would block this if it sees it
}

// ScanParserDiscrepancy probes for header parsing discrepancies between front and back-end.
func ScanParserDiscrepancy(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("ParserDiscrepancy probe: %s", target.Host)
	dbg(cfg, "Parser: starting, target=%s", target.Host)

	// Strip to a clean base: only keep essential headers
	clean := buildCleanRequest(base, target)

	canaries := []canaryHeader{
		{name: "Host-invalid", headerName: "Host", value: "foo/bar", shouldBlock: true},
		{name: "CL-invalid", headerName: "Content-Length", value: "Z", shouldBlock: true},
		{name: "Host-valid-missing", headerName: "Host", value: target.Hostname(), shouldBlock: false},
	}
	// In research mode, also test CL-valid (Content-Length: 5) which can cause timeouts
	// on vulnerable targets — matches ParserDiscrepancyScan.java research mode behaviour.
	if cfg.ResearchMode {
		canaries = append(canaries, canaryHeader{
			name: "CL-valid", headerName: "Content-Length", value: "5", shouldBlock: true,
		})
	}

	hideTechs := []hideTechnique{hideSpace, hideTab, hideWrap, hideHop, hideLpad}

	// Baseline: clean request with no canary
	baseResp, _, baseTimedOut, err := request.RawRequest(target, clean, cfg)
	if err != nil || baseTimedOut {
		rep.Log("ParserDiscrepancy: baseline failed, skipping")
		return
	}
	baseStatus := request.StatusCode(baseResp)
	dbg(cfg, "Parser: baseline status=%d", baseStatus)

	for _, canary := range canaries {
		for _, hide := range hideTechs {
			probeReq := injectHiddenHeader(clean, canary.headerName, canary.value, hide)
			if probeReq == nil {
				continue
			}

			resp, _, timedOut, err := request.RawRequest(target, probeReq, cfg)
			if err != nil || timedOut {
				dbg(cfg, "Parser [%s/%s]: err/timeout", canary.name, hide)
				continue
			}

			probeStatus := request.StatusCode(resp)
			dbg(cfg, "Parser [%s/%s]: probe_status=%d base=%d", canary.name, hide, probeStatus, baseStatus)
			interesting := false
			desc := ""

			if canary.shouldBlock {
				// If the canary should be blocked by front-end but we got a 200-ish:
				// back-end saw it (front-end didn't strip it) OR back-end tolerates it differently
				if probeStatus != baseStatus {
					interesting = true
					desc = fmt.Sprintf("status changed %d→%d with hidden %s header (technique=%s); "+
						"possible parser discrepancy allowing desync", baseStatus, probeStatus, canary.name, hide)
				}
			} else {
				// If the canary should be forwarded: if back-end rejects it, discrepancy
				if probeStatus >= 400 && baseStatus < 400 {
					interesting = true
					desc = fmt.Sprintf("status %d with %s (hidden via %s) suggests back-end rejects header front-end forwards",
						probeStatus, canary.name, hide)
				}
			}

			if interesting {
				// Confirm consistency
				confirmedCount := 0
				for i := 0; i < cfg.ConfirmReps; i++ {
					r2, _, t2, e2 := request.RawRequest(target, probeReq, cfg)
					if e2 != nil || t2 {
						continue
					}
					if request.StatusCode(r2) == probeStatus {
						confirmedCount++
					}
				}
				if confirmedCount == 0 {
					rep.Log("ParserDiscrepancy: inconsistent result for %s/%s, skipping", canary.name, hide)
					continue
				}

				rep.Emit(report.Finding{
					Target:      target.String(),
					Method:      config.EffectiveMethods(cfg)[0],
					Severity:    report.SeverityInfo,
					Type:        "parser-discrepancy",
					Technique:   string(hide) + "/" + canary.name,
					Description: desc,
					RawProbe:    request.Truncate(string(probeReq), 512),
					RawResponse: request.Truncate(request.SanitizeResponse(resp), 256),
				})
				if cfg.ExitOnFind {
					return
				}
			}
		}
	}
}

// injectHiddenHeader injects a header into the request, hidden from the front-end
// using a specific technique. Each technique maps exactly to the corresponding
// HideTechnique in HiddenPair.java:
//
//   SPACE  → header name has trailing space: "Content-Length : Z"
//            Some front-ends reject the non-standard name and strip it; the
//            back-end may normalise the trailing space and accept it.
//
//   TAB    → header name has trailing tab: "Content-Length\t: Z"
//            Same principle as SPACE but with a tab character.
//
//   WRAP   → value starts with CRLF + space (obsolete line folding RFC 7230 §3.2.6):
//            "Content-Length: \r\n Z"
//            Front-end may see an empty/invalid value and strip the header; the
//            back-end normalises the folded value to "Z".
//
//   HOP    → mark the canary header as hop-by-hop via Connection header:
//            "Content-Length: Z" + "Connection: Content-Length"
//            The front-end strips headers listed in Connection before forwarding.
//
//   LPAD   → prepend an X-Junk header whose value appears to continue on the
//            next line (line-folding trick): "X-Junk: x\r\n Content-Length: Z"
//            The leading space makes the canary look like a continuation of
//            X-Junk; parsers that don't support folding may see it as a new header.
func injectHiddenHeader(req []byte, headerName, headerValue string, technique hideTechnique) []byte {
	switch technique {
	case hideSpace:
		// Trailing space on header NAME: "Content-Length : Z"
		// (name + " " + ": " + value → "Content-Length : Z")
		return appendHeaderBeforeSep(req, headerName+" : "+headerValue)

	case hideTab:
		// Trailing tab on header NAME: "Content-Length\t: Z"
		return appendHeaderBeforeSep(req, headerName+"\t: "+headerValue)

	case hideWrap:
		// Obsolete line folding in header VALUE: "Content-Length: \r\n Z"
		// The front-end may see an empty value and drop the header; the back-end
		// normalises the folded line to Content-Length: Z.
		return appendHeaderBeforeSep(req, headerName+": \r\n "+headerValue)

	case hideHop:
		// Mark header as hop-by-hop: add the canary header first, then
		// Connection listing it so the front-end strips it before forwarding.
		r := appendHeaderBeforeSep(req, headerName+": "+headerValue)
		return appendHeaderBeforeSep(r, "Connection: "+headerName)

	case hideLpad:
		// X-Junk header whose value appears to continue on the next line:
		// "X-Junk: x\r\n Content-Length: Z"
		// The leading space makes parsers that don't support line folding treat
		// " Content-Length" as a continuation of X-Junk's value and ignore it,
		// while other back-ends parse it as an independent header.
		return appendHeaderBeforeSep(req, "X-Junk: x\r\n "+headerName+": "+headerValue)

	default:
		return nil
	}
}

// appendHeaderBeforeSep inserts a header line (without trailing \r\n) just before
// the blank line (\r\n\r\n) that separates headers from the body.
// It adds exactly one \r\n before the new line, producing well-formed HTTP.
func appendHeaderBeforeSep(req []byte, line string) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(req, sep)
	if idx < 0 {
		return req
	}
	var buf bytes.Buffer
	buf.Write(req[:idx])
	buf.WriteString("\r\n")
	buf.WriteString(line)
	buf.Write(req[idx:]) // includes \r\n\r\n and body
	return buf.Bytes()
}

// buildCleanRequest builds a minimal request keeping only safe essential headers.
func buildCleanRequest(base []byte, target *url.URL) []byte {
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	_ = base // could extract Accept/Accept-Encoding from original but keep it minimal
	return []byte(b.String())
}
