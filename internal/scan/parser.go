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
	noHost      bool // build base request without Host header (for Host injection tests)
}

// ScanParserDiscrepancy probes for header parsing discrepancies between front and back-end.
//
// For each (canary, technique) pair, four "hidden pair" variants are tested —
// matching ParserDiscrepancyScan.java + HiddenPair.java:
//
//  1. z-prefix, direct:   technique applied to z-prefixed name (zontent-Length, zost)
//  2. real, direct:       technique applied to real name (Content-Length, Host)
//  3. z-prefix, indirect: z-prefixed header standalone + "dummy" header hidden via technique
//  4. real, indirect:     real header standalone + "dummy" header hidden via technique
func ScanParserDiscrepancy(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("ParserDiscrepancy probe: %s", target.Host)
	dbg(cfg, "Parser: starting, target=%s", target.Host)

	// Strip to a clean base: only keep essential headers
	clean := buildCleanRequest(base, target)
	cleanNoHost := buildCleanRequestNoHost(base, target)

	canaries := []canaryHeader{
		// CL-valid: numeric value 5. Burp tests this in the standard (non-research)
		// scan — it causes the back-end to wait for 5 bytes when CL.0 is in effect.
		{name: "CL-valid", headerName: "Content-Length", value: "5", shouldBlock: true},
		// CL-invalid: non-numeric value. Back-ends that parse this as CL=0 desync.
		{name: "CL-invalid", headerName: "Content-Length", value: "Z", shouldBlock: true},
		// Host-valid-missing: base request has NO Host header; hidden-only injection.
		// Tests if back-end accepts a Host that the front-end never saw as a top-level header.
		{name: "Host-valid-missing", headerName: "Host", value: target.Hostname(), shouldBlock: false, noHost: true},
		// Host-invalid: base has a normal Host; we inject a SECOND invalid Host value.
		{name: "Host-invalid", headerName: "Host", value: "foo/bar", shouldBlock: true},
	}

	hideTechs := []hideTechnique{hideLpad, hideHop, hideWrap, hideTab, hideSpace}

	// Baseline: clean request with no canary
	baseResp, _, baseTimedOut, err := request.RawRequest(target, clean, cfg)
	if err != nil || baseTimedOut {
		rep.Log("ParserDiscrepancy: baseline failed, skipping")
		return
	}
	baseStatus := request.StatusCode(baseResp)
	dbg(cfg, "Parser: baseline status=%d", baseStatus)

	for _, canary := range canaries {
		canaryBase := clean
		if canary.noHost {
			canaryBase = cleanNoHost
		}
		zName := zPrefixHeader(canary.headerName)

		for _, hide := range hideTechs {
			// Build all 4 hidden-pair variants for this (canary, technique) pair,
			// each paired with a "missing" control that applies the same technique
			// to a neutral "dummy" header instead of the real canary header.
			//
			// This mirrors Java's PermutationResult 4-way matrix:
			//   hiddenCanaryPresent = technique applied with canary header
			//   hiddenCanaryMissing = same technique structure, dummy header only
			//
			// DISCREPANCY condition (PermutationResult.classify() line 362):
			//   hiddenPresent != hiddenMissing   → technique has different effect when canary present
			//   hiddenMissing  == canaryMissing  → technique alone is neutral (= baseStatus)
			//   hiddenPresent  != canaryPresent  → canary IS visible without hiding
			//
			// The missing control is the critical FP filter: if the hiding technique
			// itself (irrespective of the canary) causes the status change, both
			// hiddenPresent and hiddenMissing will differ from baseline, and we bail.
			dummyMissing := injectHiddenHeader(canaryBase, "dummy", canary.value, hide)

			type pairVariant struct {
				label   string
				req     []byte // hiddenCanaryPresent
				missing []byte // hiddenCanaryMissing control
			}
			variants := []pairVariant{
				// 1. z-prefix, direct: technique applied to z-prefixed header name
				{
					label:   "z/" + string(hide),
					req:     injectHiddenHeader(canaryBase, zName, canary.value, hide),
					missing: dummyMissing,
				},
				// 2. real, direct: technique applied to real header name
				{
					label:   string(hide),
					req:     injectHiddenHeader(canaryBase, canary.headerName, canary.value, hide),
					missing: dummyMissing,
				},
				// 3. z-prefix, indirect: z-prefix header in normal position + dummy hidden via technique
				{
					label:   "z-indirect/" + string(hide),
					req:     injectHiddenIndirect(canaryBase, zName, canary.value, hide),
					missing: dummyMissing,
				},
				// 4. real, indirect: real header in normal position + dummy hidden via technique
				{
					label:   "indirect/" + string(hide),
					req:     injectHiddenIndirect(canaryBase, canary.headerName, canary.value, hide),
					missing: dummyMissing,
				},
			}

			for _, v := range variants {
				if v.req == nil {
					continue
				}

				// hiddenCanaryPresent probe
				resp, _, timedOut, err := request.RawRequest(target, v.req, cfg)
				if err != nil || timedOut {
					dbg(cfg, "Parser [%s/%s]: hiddenPresent err/timeout", canary.name, v.label)
					continue
				}
				hiddenPresentStatus := request.StatusCode(resp)

				// hiddenCanaryMissing control probe
				missingResp, _, missingTimedOut, missingErr := request.RawRequest(target, v.missing, cfg)
				if missingErr != nil || missingTimedOut {
					dbg(cfg, "Parser [%s/%s]: hiddenMissing err/timeout", canary.name, v.label)
					continue
				}
				hiddenMissingStatus := request.StatusCode(missingResp)

				dbg(cfg, "Parser [%s/%s]: hiddenPresent=%d hiddenMissing=%d base=%d",
					canary.name, v.label, hiddenPresentStatus, hiddenMissingStatus, baseStatus)

				// DISCREPANCY: technique has a canary-dependent effect AND the
				// technique alone is neutral (hiddenMissing == baseline).
				// Without the missing control we'd fire on any technique-induced 400.
				discrepancy := hiddenPresentStatus != hiddenMissingStatus &&
					hiddenMissingStatus == baseStatus &&
					hiddenPresentStatus != baseStatus

				if !discrepancy {
					continue
				}

				var desc string
				if canary.shouldBlock {
					desc = fmt.Sprintf(
						"Parser discrepancy: hidden %s header (technique=%s) produced status %d "+
							"(base=%d), but same technique on dummy header produced %d (= base). "+
							"The technique hid the canary from the front-end while the back-end still acted on it.",
						canary.name, v.label, hiddenPresentStatus, baseStatus, hiddenMissingStatus)
				} else {
					desc = fmt.Sprintf(
						"Parser discrepancy: hidden %s header (technique=%s) produced status %d "+
							"(base=%d), back-end rejected a header the front-end never saw.",
						canary.name, v.label, hiddenPresentStatus, baseStatus)
				}

				// Confirmation: repeat hiddenPresent probe cfg.ConfirmReps times.
				// Mirrors Java's consistent(3) — all 4 responses must be stable.
				confirmedCount := 0
				for i := 0; i < cfg.ConfirmReps; i++ {
					r2, _, t2, e2 := request.RawRequest(target, v.req, cfg)
					if e2 != nil || t2 {
						continue
					}
					if request.StatusCode(r2) == hiddenPresentStatus {
						confirmedCount++
					}
				}
				if confirmedCount == 0 {
					rep.Log("ParserDiscrepancy: inconsistent result for %s/%s, skipping", canary.name, v.label)
					continue
				}

				rep.Emit(report.Finding{
					Target:    target.String(),
					Method:    config.EffectiveMethods(cfg)[0],
					Severity:  report.SeverityInfo,
					Type:      "parser-discrepancy",
					Technique: v.label + "/" + canary.name,
					Description: desc,
					Evidence: fmt.Sprintf(
						"hiddenPresent=%d hiddenMissing=%d base=%d technique=%s canary=%s",
						hiddenPresentStatus, hiddenMissingStatus, baseStatus, v.label, canary.name),
					RawProbe:    request.Truncate(string(v.req), 512),
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

// zPrefixHeader replaces the first character of a header name with 'z'.
// This mirrors HiddenPair.java's z-prefix obfuscation:
//   Content-Length → zontent-Length
//   Host           → zost
func zPrefixHeader(name string) string {
	if name == "" {
		return "z"
	}
	return "z" + name[1:]
}

// injectHiddenIndirect injects the canary header as a plain standalone header,
// then hides a "dummy" header with the same value using the given technique.
// This matches HiddenPair.java's "indirect" pair variant:
//   e.g. for hideSpace + Content-Length: Z →
//     Content-Length: Z\r\n
//     dummy : Z
func injectHiddenIndirect(req []byte, headerName, headerValue string, technique hideTechnique) []byte {
	// Add standalone canary header (unhidden)
	r := appendHeaderBeforeSep(req, headerName+": "+headerValue)
	// Add "dummy" header with same value, hidden via the technique
	return injectHiddenHeader(r, "dummy", headerValue, technique)
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

// buildCleanRequestNoHost builds a minimal request without a Host header.
// Used for "Host-valid-missing" canary tests where the Host header is
// injected exclusively via the hiding technique (not at the normal position).
func buildCleanRequestNoHost(base []byte, target *url.URL) []byte {
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	// No Host header — the canary injection provides it via the hide technique
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("\r\n")
	_ = base
	return []byte(b.String())
}
