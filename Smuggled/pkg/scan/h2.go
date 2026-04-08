package scan

// ScanH2Downgrade detects HTTP/2-to-HTTP/1.1 downgrade smuggling.
// (Mirrors HTTP2Scan.java, H2TunnelScan.java, HiddenHTTP2.java)
//
// H2 downgrade attacks work because HTTP/2 frames are translated to HTTP/1.1
// by the front-end.  If we inject CRLF or extra headers into H2 pseudo-header
// values, they may be forwarded verbatim into the HTTP/1.1 header block,
// causing the back-end to misparse the request.
//
// We detect this by:
//   1. Confirming the server speaks HTTP/2 (look for "HTTP/2" in response).
//   2. Sending a normal H2 request and noting baseline status/body.
//   3. Injecting crafted headers (CRLF-in-value, transfer-encoding injection,
//      fake pseudo-headers, etc.) and checking for response anomalies.
//
// Since we're operating as a standalone CLI without ALPN negotiation support
// in most environments, we simulate H2-downgrade by injecting the equivalent
// HTTP/1.1 request that a vulnerable proxy would produce.

import (
	"bytes"
	"fmt"
	"time"

	"smuggled.tool/pkg/permute"
	"smuggled.tool/pkg/transport"
)

type h2Technique struct {
	name   string
	mutate func(req []byte, t Target) []byte
}

var h2Techniques = []h2Technique{
	{
		// H2.TE: inject Transfer-Encoding: chunked via CRLF in header value
		// (mirrors http2hide permutation)
		name: "h2-te-injection",
		mutate: func(req []byte, t Target) []byte {
			return permute.AddOrReplaceHeader(req, "Foo", "b\r\nTransfer-Encoding: chunked\r\nx")
		},
	},
	{
		// H2.CL: inject a conflicting Content-Length
		name: "h2-cl-injection",
		mutate: func(req []byte, t Target) []byte {
			return permute.AddOrReplaceHeader(req, "Content-Length", "0")
		},
	},
	{
		// H2.TE via colon in header name (h2colon)
		name: "h2-colon",
		mutate: func(req []byte, t Target) []byte {
			return permute.AddOrReplaceHeader(req, "Transfer-Encoding`chunked ", "chunked")
		},
	},
	{
		// H2 prefix pseudo-header injection
		name: "h2-prefix",
		mutate: func(req []byte, t Target) []byte {
			r := permute.AddOrReplaceHeader(req, ":transfer-encoding", "chunked")
			return r
		},
	},
	{
		// Inject CRLF into :authority to smuggle a header
		name: "h2-authority-inject",
		mutate: func(req []byte, t Target) []byte {
			// Simulate what a vulnerable proxy would forward after CRLF injection
			return permute.AddOrReplaceHeader(req, "Host",
				fmt.Sprintf("%s:443\r\nTransfer-Encoding: chunked\r\nx: x", t.Host))
		},
	},
	{
		// Method injection via :method pseudo-header
		name: "h2-method-inject",
		mutate: func(req []byte, t Target) []byte {
			return permute.SetMethod(req,
				fmt.Sprintf("POST %s HTTP/1.1\r\nTransfer-Encoding: chunked\r\nFoo", t.Path))
		},
	},
	{
		// H2.TE via scheme injection
		name: "h2-scheme-inject",
		mutate: func(req []byte, t Target) []byte {
			return permute.AddOrReplaceHeader(req, "X-Scheme",
				fmt.Sprintf("https://%s%s HTTP/1.1\r\nTransfer-Encoding: chunked\r\nx: x", t.Host, t.Path))
		},
	},
}

// ScanH2Downgrade probes for HTTP/2 downgrade smuggling vulnerabilities.
func ScanH2Downgrade(t Target, baseReq []byte, opts Options) []Finding {
	var findings []Finding
	connCfg := t.Conn
	connCfg.Timeout = opts.Timeout
	connCfg.ProxyURL = opts.ProxyURL

	// Quick H2 probe: try to establish a TLS connection and check ALPN
	// If the server doesn't speak H2, skip (informational).
	if connCfg.TLS {
		if !probeH2Support(connCfg) {
			if opts.Verbose {
				logf("  h2-downgrade: server doesn't appear to support HTTP/2, skipping")
			}
			return nil
		}
	}

	// Baseline via plain HTTP/1.1
	baseResp := transport.SendAndReceive(connCfg, baseReq)
	if isTimeout(baseResp) || baseResp.StatusCode == 0 {
		return nil
	}
	baseStatus := baseResp.StatusCode

	for _, tech := range h2Techniques {
		if !techniqueEnabled(tech.name, opts) && len(opts.OnlyTechniques) > 0 {
			continue
		}

		mutated := tech.mutate(baseReq, t)
		if mutated == nil || bytes.Equal(mutated, baseReq) {
			continue
		}

		if opts.Verbose {
			logf("  h2-downgrade [%s] → %s", tech.name, t.Host)
		}

		resp := transport.SendAndReceive(connCfg, mutated)
		if resp.Error != nil || resp.StatusCode == 0 {
			continue
		}

		// H2 injection signals: 400 (bad request due to malformed forwarded header),
		// timeout (back-end waiting for smuggled chunk body), or response body anomaly
		if !h2IsInteresting(baseStatus, resp, tech.name) {
			continue
		}

		// Confirm
		confirmed := confirm(opts.ConfirmRounds, func() bool {
			cr := transport.SendAndReceive(connCfg, mutated)
			return h2IsInteresting(baseStatus, cr, tech.name)
		})
		if !confirmed {
			continue
		}

		severity := SeverityProbable
		if resp.TimedOut {
			severity = SeverityConfirmed // timeout is a strong signal
		}

		findings = append(findings, Finding{
			URL:       t.RawURL,
			Technique: tech.name,
			Type:      "H2.TE",
			Severity:  severity,
			Description: fmt.Sprintf(
				"HTTP/2 downgrade smuggling ('%s'): injected header caused "+
					"status %d vs baseline %d. A vulnerable H2→H1 proxy may be "+
					"forwarding injected headers verbatim into the HTTP/1.1 rewrite.",
				tech.name, resp.StatusCode, baseStatus,
			),
			Evidence: fmt.Sprintf(
				"Baseline status: %d | Probe status: %d | Timed out: %v\n\nProbe:\n%s",
				baseStatus, resp.StatusCode, resp.TimedOut,
				sanitiseForLog(mutated, 512),
			),
			Timestamp: time.Now(),
		})

		if opts.Verbose {
			logf("  [!] H2 downgrade '%s' on %s (base=%d, probe=%d, to=%v)",
				tech.name, t.RawURL, baseStatus, resp.StatusCode, resp.TimedOut)
		}
	}

	return findings
}

func h2IsInteresting(baseStatus int, resp transport.Response, techName string) bool {
	if resp.StatusCode == 0 {
		return false
	}
	// Timeout = back-end waiting for body we injected → strong signal
	if resp.TimedOut {
		return true
	}
	// Status class change
	if statusClass(resp.StatusCode) != statusClass(baseStatus) {
		return true
	}
	// 400 specifically often means the proxy forwarded our injected header
	if resp.StatusCode == 400 && baseStatus != 400 {
		return true
	}
	return false
}

// probeH2Support checks if a TLS server advertises h2 via ALPN.
// We do this by checking the TLS handshake negotiated protocol.
func probeH2Support(connCfg transport.ConnConfig) bool {
	// Simple heuristic: try to connect and check for HTTP/2 indicators
	// in a normal HTTPS response header (e.g., "HTTP/2" in response line
	// or an Upgrade header).
	probe := buildH2Probe(connCfg)
	resp := transport.SendAndReceive(connCfg, probe)
	if resp.Error != nil {
		return false
	}
	// Check for HTTP/2 indicators in response
	return bytes.Contains(resp.Raw, []byte("HTTP/2")) ||
		bytes.Contains(resp.Raw, []byte("h2")) ||
		resp.Headers["upgrade"] == "h2" ||
		resp.Headers["Upgrade"] == "h2"
}

func buildH2Probe(connCfg transport.ConnConfig) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET / HTTP/1.1\r\n")
	fmt.Fprintf(&b, "Host: %s\r\n", connCfg.Host)
	b.WriteString("Connection: Upgrade, HTTP2-Settings\r\n")
	b.WriteString("Upgrade: h2c\r\n")
	b.WriteString("HTTP2-Settings: AAMAAABkAAQAAP__\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}
