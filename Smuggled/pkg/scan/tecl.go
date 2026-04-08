package scan

// ScanTECL detects TE.CL desync: front-end uses Transfer-Encoding,
// back-end uses Content-Length.
//
// Detection strategy (mirrors ChunkContentScan.java TE.CL path):
//
//  1. Send a chunked request where the Content-Length is intentionally SMALLER
//     than the actual body (it points only into the prefix of the chunk, not
//     past the 0-terminator).  If the back-end respects CL and stops reading
//     early, it closes the connection after consuming exactly CL bytes —
//     leaving the remainder in its buffer to be interpreted as the start of a
//     new request.
//
//  2. Timeout signal: the poisoned remainder is "0\r\n\r\n" or similar, which
//     the back-end will try to parse as a new request method — and will block
//     waiting for a full request line, manifesting as a hang.
//
//  3. Confirmation: repeat N times, require consistent timeout.

import (
	"bytes"
	"fmt"
	"time"

	"smuggled.tool/pkg/permute"
	"smuggled.tool/pkg/transport"
)

// ScanTECL tries all TE permutations looking for TE.CL desync.
func ScanTECL(t Target, baseReq []byte, opts Options) []Finding {
	var findings []Finding
	connCfg := t.Conn
	connCfg.Timeout = opts.Timeout
	connCfg.ProxyURL = opts.ProxyURL

	techs := permute.AllTEPermutations()

	for _, tech := range techs {
		if !techniqueEnabled(tech.Name, opts) {
			continue
		}

		mutated := tech.Apply(baseReq)
		if mutated == nil || bytes.Equal(mutated, baseReq) && tech.Name != "vanilla" {
			continue
		}

		if opts.Verbose {
			logf("  TE.CL [%s] → %s", tech.Name, t.Host)
		}

		finding := probeTECL(t, mutated, connCfg, opts, tech.Name)
		if finding != nil {
			findings = append(findings, *finding)
			if opts.Verbose {
				logf("  [!] TE.CL confirmed with technique '%s' on %s", tech.Name, t.RawURL)
			}
			break
		}
	}
	return findings
}

func probeTECL(t Target, req []byte, connCfg transport.ConnConfig, opts Options, techName string) *Finding {
	body := permute.GetBody(req)
	if body == "" {
		body = "x=y"
	}

	// Step 1 — baseline: full well-formed chunked request
	syncedReq := buildTECLSynced(req, body, 0)
	baselineResp := transport.SendAndReceive(connCfg, syncedReq)
	if isTimeout(baselineResp) {
		return nil
	}
	if baselineResp.Error != nil {
		return nil
	}

	// Step 2 — undersized CL probe
	// CL points to end of chunk data but before the terminal "0\r\n\r\n",
	// so the back-end consumes the chunk, then receives "0\r\n\r\n" as a
	// new request → stalls waiting for valid method line.
	poisonReq := buildTECLPoison(req, body)
	poisonResp := transport.SendAndReceive(connCfg, poisonReq)
	if !poisonResp.TimedOut {
		return nil
	}

	// Step 3 — anti-FP: baseline must still be fast
	baselineResp2 := transport.SendAndReceive(connCfg, syncedReq)
	if isTimeout(baselineResp2) {
		return nil // target became unresponsive — FP
	}

	// Step 4 — repeat confirmation
	confirmed := confirm(opts.ConfirmRounds, func() bool {
		r := transport.SendAndReceive(connCfg, poisonReq)
		return r.TimedOut
	})
	if !confirmed {
		return nil
	}

	return &Finding{
		URL:       t.RawURL,
		Technique: techName,
		Type:      "TE.CL",
		Severity:  SeverityConfirmed,
		Description: fmt.Sprintf(
			"TE.CL desync confirmed with technique '%s'. The front-end parsed "+
				"Transfer-Encoding while the back-end used Content-Length, "+
				"leaving residual bytes poisoning the connection pipeline.",
			techName,
		),
		Evidence:  buildTECLEvidence(poisonReq, opts.Timeout),
		Timestamp: time.Now(),
	}
}

// buildTECLSynced builds a normal chunked request — CL equals actual body len.
func buildTECLSynced(req []byte, body string, offset int) []byte {
	chunkedBody := permute.BuildChunkedBody(body, offset)
	r := permute.SetBody(req, chunkedBody)
	r = permute.AddOrReplaceHeader(r, "Connection", "close")
	return r
}

// buildTECLPoison builds the undersized-CL probe.
// Content-Length is set to point just BEFORE the terminal chunk,
// so the back-end (using CL) reads the data portion and stops,
// leaving "0\r\n\r\n" on the wire as a ghost request.
func buildTECLPoison(req []byte, body string) []byte {
	if body == "" {
		body = "x=y"
	}
	// Full chunked body
	chunkData := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)
	// CL points to just the chunk-size line + body, NOT the terminator
	cl := len(fmt.Sprintf("%x\r\n%s\r\n", len(body), body))

	r := permute.AddOrReplaceHeader(req, "Transfer-Encoding", "chunked")
	r = permute.AddOrReplaceHeader(r, "Connection", "close")

	// Replace body raw (bypass the SetBody helper which rewrites CL automatically)
	sep := bytes.Index(r, []byte("\r\n\r\n"))
	if sep == -1 {
		return r
	}
	result := make([]byte, sep+4+len(chunkData))
	copy(result, r[:sep+4])
	copy(result[sep+4:], []byte(chunkData))

	// Now force CL to the undersized value
	result = permute.AddOrReplaceHeader(result, "Content-Length", fmt.Sprintf("%d", cl))
	// Lowercase CL to bypass some front-end CL-enforcement middleware
	result = bytes.Replace(result, []byte("Content-Length: "), []byte("Content-length: "), 1)
	return result
}

func buildTECLEvidence(probe []byte, timeout time.Duration) string {
	return fmt.Sprintf(
		"Probe with undersized Content-Length timed out after %s, "+
			"consistent with TE.CL desync.\n\nPayload snippet:\n%s",
		timeout,
		sanitiseForLog(probe, 512),
	)
}
