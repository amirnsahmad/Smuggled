package scan

// h2.go — HTTP/2 downgrade desync detection
//
// Maps to HTTP2Scan.java, H2TunnelScan.java, HiddenHTTP2.java.
//
// Strategy:
// When a front-end accepts HTTP/2 and downgrades to HTTP/1.1 for the back-end,
// H2-specific headers or header injection can smuggle a request that the back-end
// sees as a second, separate HTTP/1.1 request.
//
// We use Go's net/http with HTTP/2 forced via h2c or TLS-ALPN, then craft
// requests with injected newlines in header values (H2.TE, H2.CL).
//
// Note: true H2 framing with injected CRLF in header values requires
// a custom HPACK encoder — here we approximate via golang.org/x/net/http2
// and test the most reliable downgrade vectors.

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
	"github.com/smuggled/smuggled/pkg/transport"
)

// ScanH2Downgrade probes for HTTP/2 → HTTP/1.1 downgrade desync vectors.
func ScanH2Downgrade(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	if target.Scheme != "https" {
		rep.Log("H2Downgrade: skipping non-HTTPS target %s", target.Host)
		return
	}

	rep.Log("H2Downgrade probe: %s", target.Host)

	// First check if server supports HTTP/2
	if !supportsH2(target, cfg) {
		rep.Log("H2Downgrade: %s does not advertise h2 via ALPN, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	// H2.TE: inject Transfer-Encoding: chunked via H2 header value with CRLF
	// The front-end accepts it as an H2 field, but when downgraded to H1 it creates
	// a second TE header that the back-end processes for chunked body handling.
	teInjectionTechniques := []struct {
		name  string
		value string
	}{
		{"H2.TE-crlf", "chunked\r\nTransfer-Encoding: chunked"},
		{"H2.TE-lf", "chunked\nTransfer-Encoding: chunked"},
		{"H2.CL-inject", "0\r\nContent-Length: 99"},
		{"H2.host-inject", host + "\r\nTransfer-Encoding: chunked"},
	}

	for _, tech := range teInjectionTechniques {
		rep.Log("H2Downgrade: technique=%s", tech.name)

		resp, elapsed, err := h2RequestWithInjectedHeader(target, path, host,
			"transfer-encoding", tech.value, cfg)
		if err != nil {
			rep.Log("H2Downgrade %s error: %v", tech.name, err)
			continue
		}

		if elapsed > time.Duration(float64(cfg.Timeout)*timeoutRatio) {
			rep.Emit(report.Finding{
				Target:      target.String(),
				Severity:    report.SeverityProbable,
				Type:        "H2.TE",
				Technique:   tech.name,
				Description: "H2→H1 downgrade with injected TE header caused timeout — possible H2.TE desync",
				Evidence:    fmt.Sprintf("elapsed=%v injected_value=%q", elapsed, tech.value),
			})
			continue
		}

		if isSuspiciousResponse(resp) {
			rep.Emit(report.Finding{
				Target:      target.String(),
				Severity:    report.SeverityProbable,
				Type:        "H2.TE",
				Technique:   tech.name,
				Description: fmt.Sprintf("H2→H1 downgrade with injected TE header returned status %d — possible desync", statusCode(resp)),
				Evidence:    fmt.Sprintf("status=%d elapsed=%v", statusCode(resp), elapsed),
			})
		}
	}

	// H2.CL: inject a Content-Length that conflicts with the actual body length
	h2CLDesync(target, path, host, cfg, rep)
}

// h2RequestWithInjectedHeader sends a raw HTTP/2 request with a header whose
// value contains injected CRLF or newline sequences to test for H2→H1 downgrade.
func h2RequestWithInjectedHeader(target *url.URL, path, host, headerName, headerValue string, cfg Config) ([]byte, time.Duration, error) {
	addr := target.Hostname() + ":443"
	if p := target.Port(); p != "" {
		addr = target.Hostname() + ":" + p
	}

	tlsCfg := &tls.Config{
		ServerName:         target.Hostname(),
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec
		NextProtos:         []string{"h2"},
	}

	netDialer := &net.Dialer{Timeout: cfg.Timeout}
	rawConn, err := tls.DialWithDialer(netDialer, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, 0, fmt.Errorf("tls dial: %w", err)
	}
	defer rawConn.Close()

	if rawConn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, 0, fmt.Errorf("server did not negotiate h2")
	}

	// Write HTTP/2 client preface
	rawConn.SetDeadline(time.Now().Add(cfg.Timeout)) //nolint:errcheck
	if _, err := rawConn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, 0, err
	}

	framer := http2.NewFramer(rawConn, rawConn)
	framer.AllowIllegalWrites = true
	framer.AllowIllegalReads = true

	// Send SETTINGS frame
	if err := framer.WriteSettings(); err != nil {
		return nil, 0, err
	}

	// Encode HEADERS with injected value
	var headersBuf bytes.Buffer
	enc := hpack.NewEncoder(&headersBuf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: host})
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/x-www-form-urlencoded"})
	enc.WriteField(hpack.HeaderField{Name: "content-length", Value: "3"})
	// Inject the malformed header
	enc.WriteField(hpack.HeaderField{Name: headerName, Value: headerValue, Sensitive: false})

	start := time.Now()

	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: headersBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return nil, 0, err
	}

	// Send DATA frame with minimal body
	if err := framer.WriteData(1, true, []byte("x=y")); err != nil {
		return nil, 0, err
	}

	// Read response frames
	var respBuf bytes.Buffer
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			break
		}
		switch f := frame.(type) {
		case *http2.DataFrame:
			respBuf.Write(f.Data())
		case *http2.HeadersFrame:
			respBuf.Write(f.HeaderBlockFragment())
		case *http2.RSTStreamFrame:
			goto done
		case *http2.GoAwayFrame:
			goto done
		}
	}
done:
	elapsed := time.Since(start)
	return respBuf.Bytes(), elapsed, nil
}

// h2CLDesync tests for H2.CL desync where CL in an H2 request conflicts with actual body.
func h2CLDesync(target *url.URL, path, host string, cfg Config, rep *report.Reporter) {
	// Send H2 request with CL=99 but only 3 bytes of body.
	// If back-end uses CL (from the downgraded H1 request), it waits for 96 more bytes.
	resp, elapsed, err := h2RequestWithInjectedHeader(target, path, host,
		"content-length", "99", cfg)
	if err != nil {
		return
	}

	if elapsed > time.Duration(float64(cfg.Timeout)*timeoutRatio) || len(resp) == 0 {
		rep.Emit(report.Finding{
			Target:      target.String(),
			Severity:    report.SeverityProbable,
			Type:        "H2.CL",
			Technique:   "H2.CL-mismatch",
			Description: "H2 request with inflated Content-Length caused timeout — possible H2.CL desync",
			Evidence:    fmt.Sprintf("elapsed=%v", elapsed),
		})
	}
}

// supportsH2 checks whether the server negotiates HTTP/2 via ALPN.
func supportsH2(target *url.URL, cfg Config) bool {
	addr := target.Hostname() + ":443"
	if p := target.Port(); p != "" {
		addr = target.Hostname() + ":" + p
	}
	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return false
	}
	conn.Close()

	// We need tls.Conn to inspect ALPN — re-dial with tls directly
	tlsCfg := &tls.Config{
		ServerName:         target.Hostname(),
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec
		NextProtos:         []string{"h2", "http/1.1"},
	}
	netDialer2 := &net.Dialer{Timeout: cfg.Timeout}
	tlsConn, err := tls.DialWithDialer(netDialer2, "tcp", addr, tlsCfg)
	if err != nil {
		return false
	}
	defer tlsConn.Close()

	proto := tlsConn.ConnectionState().NegotiatedProtocol
	return strings.Contains(proto, "h2")
}
