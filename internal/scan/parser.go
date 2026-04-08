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

	// Strip to a clean base: only keep essential headers
	clean := buildCleanRequest(base, target)

	canaries := []canaryHeader{
		{name: "Host-invalid", headerName: "Host", value: "foo/bar", shouldBlock: true},
		{name: "CL-invalid", headerName: "Content-Length", value: "Z", shouldBlock: true},
		{name: "Host-valid-missing", headerName: "Host", value: target.Hostname(), shouldBlock: false},
	}

	hideTechs := []hideTechnique{hideSpace, hideTab, hideWrap, hideHop, hideLpad}

	// Baseline: clean request with no canary
	baseResp, _, baseTimedOut, err := request.RawRequest(target, clean, cfg)
	if err != nil || baseTimedOut {
		rep.Log("ParserDiscrepancy: baseline failed, skipping")
		return
	}
	baseStatus := request.StatusCode(baseResp)

	for _, canary := range canaries {
		for _, hide := range hideTechs {
			probeReq := injectHiddenHeader(clean, canary.headerName, canary.value, hide)
			if probeReq == nil {
				continue
			}

			resp, _, timedOut, err := request.RawRequest(target, probeReq, cfg)
			if err != nil || timedOut {
				continue
			}

			probeStatus := request.StatusCode(resp)
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
					Severity:    report.SeverityInfo,
					Type:        "parser-discrepancy",
					Technique:   string(hide) + "/" + canary.name,
					Description: desc,
					RawProbe:    request.Truncate(string(probeReq), 512),
					RawResponse: request.Truncate(string(resp), 256),
				})
			}
		}
	}
}

// injectHiddenHeader injects a header into the request, hidden from the front-end
// using a specific technique.
func injectHiddenHeader(req []byte, headerName, headerValue string, technique hideTechnique) []byte {
	// Build the injected header line
	injectedLine := headerName + ": " + headerValue + "\r\n"

	// Find position to inject: before the blank line (\r\n\r\n)
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(req, sep)
	if idx < 0 {
		return nil
	}

	var hiddenHeader string
	switch technique {
	case hideSpace:
		// Prefix with space to make front-end see it as continuation of previous header
		hiddenHeader = " " + injectedLine
	case hideTab:
		hiddenHeader = "\t" + injectedLine
	case hideWrap:
		// Line folding (RFC 7230 §3.2.6 — obsolete but sometimes parsed)
		hiddenHeader = "\r\n " + injectedLine
	case hideHop:
		// Mark as hop-by-hop via Connection header so front-end strips it
		hiddenHeader = injectedLine
		// Prepend Connection header listing our canary header
		req = injectRaw(req, "Connection: "+headerName+"\r\n")
	case hideLpad:
		// Left-pad with a null byte (some parsers skip non-printable prefixes)
		hiddenHeader = "\x00" + injectedLine
	default:
		return nil
	}

	if technique != hideHop {
		return injectRaw(req, hiddenHeader)
	}
	return req
}

// injectRaw inserts a raw string just before the header/body separator.
func injectRaw(req []byte, raw string) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(req, sep)
	if idx < 0 {
		return req
	}
	var buf bytes.Buffer
	buf.Write(req[:idx])
	buf.WriteString("\r\n" + raw[:len(raw)-2]) // strip trailing \r\n to avoid double
	buf.Write(req[idx:])
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
