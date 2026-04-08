package scan

// ScanClientDesync implements client-side desync detection.
// (Mirrors ClientDesyncScan.java / waitScan)
//
// Strategy: send a single POST where Content-Length is set to the full length
// of a follow-up GET request, but the body is left empty.  Over a keep-alive
// connection the server should immediately process the POST then wait for the
// Content-Length bytes that never arrive.  If instead the server replies TWICE
// (once for the POST and once interpreting the follow-up GET as a request), it
// is vulnerable to client-side desync.
//
// We detect the double-response by sending two requests over the same
// persistent connection and checking whether the second response is
// anomalously fast (< ~100 ms) compared to a clean baseline.

import (
	"bytes"
	"fmt"
	"time"

	"smuggled.tool/pkg/permute"
	"smuggled.tool/pkg/transport"
)

// ScanClientDesync probes for client-side desync.
func ScanClientDesync(t Target, baseReq []byte, opts Options) []Finding {
	connCfg := t.Conn
	connCfg.Timeout = opts.Timeout
	connCfg.ProxyURL = opts.ProxyURL

	// Follow-up request that will be used as the "poisoning" suffix
	followup := buildFollowup(t)

	// Build the attack POST: CL = len(followup), body = empty
	attack := buildClientDesyncAttack(t, followup)

	if opts.Verbose {
		logf("  client-desync probe → %s", t.Host)
	}

	// Baseline: two normal requests — measure how long r2 takes
	baseR1, baseR2 := transport.SendPair(connCfg, baseReq, baseReq)
	if baseR1.Error != nil || baseR2.Error != nil {
		return nil
	}
	baselineR2Duration := baseR2.Duration

	// Attack pair: r1 is the crafted POST, r2 is a normal request
	// If the server is vulnerable, r2 arrives almost instantly (it was
	// pre-processed as part of the poisoned pipeline).
	attackR1, attackR2 := transport.SendPair(connCfg, attack, followup)
	if attackR1.Error != nil {
		return nil
	}
	if attackR2.StatusCode == 0 {
		return nil
	}

	// Double-response signal: r2 arrived significantly faster than baseline
	threshold := baselineR2Duration / 3
	if threshold < 50*time.Millisecond {
		threshold = 50 * time.Millisecond
	}
	if attackR2.Duration > threshold {
		return nil
	}

	// Confirm
	confirmed := confirm(opts.ConfirmRounds, func() bool {
		ar1, ar2 := transport.SendPair(connCfg, attack, followup)
		if ar1.Error != nil || ar2.StatusCode == 0 {
			return false
		}
		return ar2.Duration <= threshold
	})
	if !confirmed {
		return nil
	}

	if opts.Verbose {
		logf("  [!] Client-side desync on %s (r2 in %s vs baseline %s)",
			t.RawURL, attackR2.Duration, baselineR2Duration)
	}

	return []Finding{{
		URL:       t.RawURL,
		Technique: "client-desync",
		Type:      "client-desync",
		Severity:  SeverityConfirmed,
		Description: "Client-side desync detected. A single crafted POST request " +
			"caused the server to produce two responses on a single connection. " +
			"This enables browser-powered desync attacks without a co-operative " +
			"front-end proxy.",
		Evidence: fmt.Sprintf(
			"Attack r2 duration: %s | Baseline r2 duration: %s\n\nAttack payload:\n%s",
			attackR2.Duration, baselineR2Duration,
			sanitiseForLog(attack, 512),
		),
		Timestamp: time.Now(),
	}}
}

func buildFollowup(t Target) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", t.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", t.Host)
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}

func buildClientDesyncAttack(t Target, followup []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\n", t.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", t.Host)
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(followup))
	b.WriteString("Connection: keep-alive\r\n")
	b.WriteString("\r\n")
	// body intentionally empty — CL promises len(followup) bytes that won't arrive
	// via this write, so the server either waits or interprets followup as request
	req := b.Bytes()
	// Lowercase CL to bypass some middleware that enforces Content-Length
	return bytes.Replace(req, []byte("Content-Length: "), []byte("Content-length: "), 1)
}

// ─── Connection state scan (bonus) ────────────────────────────────────────────

// ScanConnectionState checks whether the server reuses connection state
// across requests — a prerequisite for many connection-state attacks.
// (Simplified mirror of ConnectionStateScan.java)
func ScanConnectionState(t Target, baseReq []byte, opts Options) []Finding {
	connCfg := t.Conn
	connCfg.Timeout = opts.Timeout
	connCfg.ProxyURL = opts.ProxyURL

	keepAlive := permute.AddOrReplaceHeader(baseReq, "Connection", "keep-alive")

	r1, r2 := transport.SendPair(connCfg, keepAlive, keepAlive)
	if r1.Error != nil || r2.Error != nil || r1.StatusCode == 0 || r2.StatusCode == 0 {
		return nil
	}

	// If Connection: close appears in the response, keep-alive is not supported
	if bytes.Contains(r1.Raw, []byte("Connection: close")) ||
		bytes.Contains(r1.Raw, []byte("connection: close")) {
		return nil
	}

	// Both requests succeeded on the same connection — note it as INFO
	if opts.Verbose {
		logf("  [i] Keep-alive connection reuse confirmed on %s", t.Host)
	}
	return nil // not a finding by itself; used internally
}
