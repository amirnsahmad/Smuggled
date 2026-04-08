package scan

// ScanParserDiscrepancy implements the v3.0 "parser discrepancy" detection
// introduced in ParserDiscrepancyScan.java.
//
// Core idea: send the same HTTP request twice — once with a "significant"
// header added in different obfuscated positions.  If the front-end and
// back-end disagree on whether the header is present/absent, we see
// different response codes or bodies.
//
// Significant canary headers used:
//   - Host-invalid: Host: foo/bar  → back-end rejects (4xx) if it sees it;
//     front-end passes it through (2xx/3xx).
//   - CL-invalid: Content-Length: Z → a non-numeric CL triggers a 4xx on
//     the back-end if the back-end is the one parsing it.
//   - CL-valid (research mode): Content-Length: 5 — sends 5 bytes of body;
//     if the front-end ignores it but the back-end reads it, the remaining
//     body poisons the next request.
//
// Hide techniques (how the canary header is concealed from one side):
//   - space:  " Significant-Header: value" (leading space → fold)
//   - tab:    "\tSignificant-Header: value"
//   - wrap:   "X-Wrap: x\r\n Significant-Header: value" (line-fold)
//   - hop:    put header in Connection: list so front-end strips it
//   - lpad:   inject header after extra blank line (some front-ends stop
//             parsing after first CRLF CRLF)

import (
	"bytes"
	"fmt"
	"time"

	"smuggled.tool/pkg/permute"
	"smuggled.tool/pkg/transport"
)

type hideTechnique int

const (
	hideSpace hideTechnique = iota
	hideTab
	hideWrap
	hideHop
	hideLpad
)

type canaryHeader struct {
	id    string
	name  string
	value string
	// expectHidden: true → we expect the back-end to see it; front-end should block/drop it
	// expectHidden: false → front-end should forward it; absence triggers back-end error
	expectHidden bool
}

var canaryHeaders = []canaryHeader{
	{"Host-invalid", "Host", "foo/bar", true},
	{"Host-valid-missing", "Host", "", false}, // filled at runtime with real host
	{"CL-invalid", "Content-Length", "Z", true},
}

var hideTechniques = []struct {
	name string
	hide hideTechnique
}{
	{"space", hideSpace},
	{"tab", hideTab},
	{"wrap", hideWrap},
	{"hop", hideHop},
	{"lpad", hideLpad},
}

// ScanParserDiscrepancy probes for front-end/back-end parser disagreements.
func ScanParserDiscrepancy(t Target, baseReq []byte, opts Options) []Finding {
	var findings []Finding
	connCfg := t.Conn
	connCfg.Timeout = opts.Timeout
	connCfg.ProxyURL = opts.ProxyURL

	// Use a stripped-down GET for parser probes
	base := buildParserBase(t)

	// Get the baseline status code
	baseResp := transport.SendAndReceive(connCfg, base)
	if isTimeout(baseResp) || baseResp.StatusCode == 0 {
		return nil
	}
	baseStatus := baseResp.StatusCode

	for _, canary := range canaryHeaders {
		// Fill in the real host for Host-valid-missing
		if canary.id == "Host-valid-missing" {
			canary.value = t.Host
		}

		for _, ht := range hideTechniques {
			if !techniqueEnabled("parser-"+canary.id+"-"+ht.name, opts) &&
				len(opts.OnlyTechniques) > 0 {
				continue
			}

			hidden := buildHiddenRequest(base, canary, ht.hide)
			if hidden == nil {
				continue
			}

			if opts.Verbose {
				logf("  parser-discrepancy [%s+%s] → %s", canary.id, ht.name, t.Host)
			}

			hiddenResp := transport.SendAndReceive(connCfg, hidden)
			if hiddenResp.Error != nil || hiddenResp.StatusCode == 0 {
				continue
			}

			if !isInteresting(baseStatus, hiddenResp.StatusCode, canary) {
				continue
			}

			// Confirm it's consistent
			confirmed := confirm(opts.ConfirmRounds, func() bool {
				r := transport.SendAndReceive(connCfg, hidden)
				return isInteresting(baseStatus, r.StatusCode, canary)
			})
			if !confirmed {
				continue
			}

			techName := fmt.Sprintf("parser:%s+%s", canary.id, ht.name)
			findings = append(findings, Finding{
				URL:       t.RawURL,
				Technique: techName,
				Type:      "parser-discrepancy",
				Severity:  SeverityConfirmed,
				Description: fmt.Sprintf(
					"Parser discrepancy detected: canary header '%s' hidden via '%s' "+
						"caused status %d vs baseline %d. "+
						"Front-end and back-end disagree on request boundaries.",
					canary.name, ht.name, hiddenResp.StatusCode, baseStatus,
				),
				Evidence: fmt.Sprintf(
					"Baseline status: %d | Hidden-canary status: %d\nTechnique: %s\n\nProbe:\n%s",
					baseStatus, hiddenResp.StatusCode, techName,
					sanitiseForLog(hidden, 512),
				),
				Timestamp: time.Now(),
			})

			if opts.Verbose {
				logf("  [!] Parser discrepancy '%s' on %s (base=%d, hidden=%d)",
					techName, t.RawURL, baseStatus, hiddenResp.StatusCode)
			}
		}
	}

	return findings
}

func buildParserBase(t Target) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", t.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", t.Host)
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n")
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}

// buildHiddenRequest injects the canary header using the given hide technique.
func buildHiddenRequest(req []byte, canary canaryHeader, hide hideTechnique) []byte {
	header := fmt.Sprintf("%s: %s", canary.name, canary.value)

	switch hide {
	case hideSpace:
		// Inject with a leading space (HTTP/1.1 obsolete line folding)
		return injectHeaderWithPrefix(req, " "+header)

	case hideTab:
		return injectHeaderWithPrefix(req, "\t"+header)

	case hideWrap:
		// Classic line-fold: X-Wrap: x\r\n <canary>
		return injectHeaderWithPrefix(req, "X-Wrap: x\r\n "+header)

	case hideHop:
		// Put canary name in Connection header so front-end strips it
		r := permute.AddOrReplaceHeader(req, "Connection", canary.name+", close")
		return permute.AddOrReplaceHeader(r, canary.name, canary.value)

	case hideLpad:
		// Inject canary after an extra blank line — some front-ends stop
		// parsing headers after first \r\n\r\n and treat rest as body
		sep := bytes.Index(req, []byte("\r\n\r\n"))
		if sep == -1 {
			return nil
		}
		var buf bytes.Buffer
		buf.Write(req[:sep])
		buf.WriteString("\r\n\r\n" + header + "\r\n")
		buf.Write(req[sep:])
		return buf.Bytes()
	}
	return nil
}

func injectHeaderWithPrefix(req []byte, prefix string) []byte {
	sep := bytes.Index(req, []byte("\r\n\r\n"))
	if sep == -1 {
		return nil
	}
	var buf bytes.Buffer
	buf.Write(req[:sep])
	buf.WriteString("\r\n" + prefix)
	buf.Write(req[sep:])
	return buf.Bytes()
}

// isInteresting returns true when the hidden-canary response differs from
// baseline in a way that indicates a parsing discrepancy.
func isInteresting(baseStatus, hiddenStatus int, canary canaryHeader) bool {
	if hiddenStatus == 0 {
		return false
	}
	if baseStatus == hiddenStatus {
		return false
	}
	// A 4xx/5xx where baseline was 2xx/3xx (or vice versa) is suspicious
	baseClass := statusClass(baseStatus)
	hiddenClass := statusClass(hiddenStatus)
	if baseClass == hiddenClass {
		return false
	}
	if canary.expectHidden {
		// We expect back-end to see it and reject (4xx); front-end should have passed it
		return hiddenClass >= 4
	}
	// We expect back-end to reject when header is absent
	return hiddenClass >= 4 && baseClass < 4
}
