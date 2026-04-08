package scan

// ScanCLTE detects CL.TE desync: front-end uses Content-Length, back-end uses
// Transfer-Encoding.  Detection strategy (mirroring ChunkContentScan.java):
//
//  1. Baseline probe — send a well-formed chunked request.  If it times out
//     the target is already unusable; skip.
//  2. Malformed-close probe — send a chunked request whose last chunk is
//     "1\r\nZ\r\nQ\r\n\r\n" (incomplete; back-end will wait for more data).
//     A normal server closes the connection quickly.
//  3. Timeout confirmation — if the malformed-close request DOES time out we
//     do a reversal probe: CL offset = -6 (causing body to be truncated from
//     the CL perspective).  If the reversal also times out we have a false
//     positive; otherwise we report CL.TE.
//  4. Anti-FP confirmation — repeat the malformed-close probe N times.

import (
	"bytes"
	"fmt"
	"time"

	"smuggled.tool/pkg/permute"
	"smuggled.tool/pkg/transport"
)

// ScanCLTE tries all TE permutations looking for CL.TE desync.
func ScanCLTE(t Target, baseReq []byte, opts Options) []Finding {
	var findings []Finding
	connCfg := t.Conn
	connCfg.Timeout = opts.Timeout
	connCfg.ProxyURL = opts.ProxyURL

	techs := permute.AllTEPermutations()

	for _, tech := range techs {
		if !techniqueEnabled(tech.Name, opts) {
			continue
		}

		// Build the mutated request with this TE permutation
		mutated := tech.Apply(baseReq)
		if mutated == nil || bytes.Equal(mutated, baseReq) && tech.Name != "vanilla" {
			continue
		}

		if opts.Verbose {
			logf("  CL.TE [%s] → %s", tech.Name, t.Host)
		}

		finding := probeCLTE(t, mutated, connCfg, opts, tech.Name)
		if finding != nil {
			findings = append(findings, *finding)
			if opts.Verbose {
				logf("  [!] CL.TE confirmed with technique '%s' on %s", tech.Name, t.RawURL)
			}
			// Once confirmed, no need to exhaust all permutations for this type
			break
		}
	}
	return findings
}

func probeCLTE(t Target, req []byte, connCfg transport.ConnConfig, opts Options, techName string) *Finding {
	body := permute.GetBody(req)
	if body == "" {
		body = "x=y"
	}

	// Step 1 — baseline: well-formed chunked request must succeed
	syncedReq := buildCLTESynced(req, body, 0, false)
	baselineResp := transport.SendAndReceive(connCfg, syncedReq)
	if isTimeout(baselineResp) {
		return nil // target unresponsive
	}

	// Step 2 — malformed-close probe (back-end must wait for the incomplete chunk)
	malformedReq := buildCLTESynced(req, body, 0, true)
	malformedResp := transport.SendAndReceive(connCfg, malformedReq)

	if !malformedResp.TimedOut {
		return nil // not vulnerable — back-end closed immediately
	}

	// Step 3 — reversal: if the reversal ALSO times out it's a FP
	reversalReq := buildCLTESynced(req, body, -6, true)
	reversalResp := transport.SendAndReceive(connCfg, reversalReq)
	if reversalResp.TimedOut {
		return nil // FP: back-end always times out regardless
	}

	// Step 4 — anti-FP confirmation loop
	confirmed := confirm(opts.ConfirmRounds, func() bool {
		r := transport.SendAndReceive(connCfg, malformedReq)
		return r.TimedOut
	})
	if !confirmed {
		return nil
	}

	return &Finding{
		URL:       t.RawURL,
		Technique: techName,
		Type:      "CL.TE",
		Severity:  SeverityConfirmed,
		Description: fmt.Sprintf(
			"CL.TE desync confirmed with technique '%s'. The front-end parsed "+
				"Content-Length while the back-end parsed Transfer-Encoding, "+
				"causing the back-end to wait for a never-arriving chunk terminator.",
			techName,
		),
		Evidence:  buildCLTEEvidence(req, malformedReq, opts.Timeout),
		Timestamp: time.Now(),
	}
}

// buildCLTESynced constructs the raw chunked request for a CL.TE probe.
// offset adjusts the Content-Length value relative to the actual body size.
// malformed=true uses an incomplete final chunk to stall the back-end.
func buildCLTESynced(req []byte, body string, offset int, malformed bool) []byte {
	var chunkedBody string
	if malformed {
		chunkedBody = permute.BuildMalformedChunkedBody(body)
	} else {
		chunkedBody = permute.BuildChunkedBody(body, 0)
	}

	r := permute.SetBody(req, chunkedBody)
	// Override CL to the offset value
	actualLen := len(chunkedBody) + offset
	if actualLen < 0 {
		actualLen = 0
	}
	r = permute.AddOrReplaceHeader(r, "Content-Length", fmt.Sprintf("%d", actualLen))
	r = permute.AddOrReplaceHeader(r, "Connection", "close")
	return r
}

func buildCLTEEvidence(original, malformed []byte, timeout time.Duration) string {
	return fmt.Sprintf(
		"Probe request (malformed chunked body) timed out after %s, "+
			"consistent with CL.TE desync.\n\nPayload snippet:\n%s",
		timeout,
		sanitiseForLog(malformed, 512),
	)
}

func sanitiseForLog(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	// replace control chars for display
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\r' && c != '\n' {
			out = append(out, '.')
		} else {
			out = append(out, c)
		}
	}
	return string(out)
}
