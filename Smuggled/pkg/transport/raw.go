// Package transport provides raw TCP/TLS socket primitives that bypass
// Go's http.Client abstractions, giving full control over framing,
// header ordering, and chunked encoding — essential for request-smuggling probes.
package transport

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"
)

// Response holds the raw bytes returned from the server plus timing metadata.
type Response struct {
	Raw        []byte
	StatusCode int
	Headers    map[string]string
	Body       []byte
	Duration   time.Duration
	TimedOut   bool
	ConnClosed bool
	Error      error
}

// ConnConfig holds parameters for a single raw connection.
type ConnConfig struct {
	Host     string
	Port     int
	TLS      bool
	Timeout  time.Duration
	ProxyURL string
	// SendDelay introduces a pause mid-send (used by pause-desync scan).
	// If > 0, the connection sends the first SendPauseAt bytes, waits SendDelay,
	// then sends the rest.
	SendDelay   time.Duration
	SendPauseAt int
}

// Dial opens a raw TCP (or TLS) connection, optionally through an HTTP CONNECT proxy.
func Dial(cfg ConnConfig) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	var conn net.Conn
	var err error

	if cfg.ProxyURL != "" {
		conn, err = dialThroughProxy(cfg.ProxyURL, addr, timeout)
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	if cfg.TLS {
		tlsCfg := &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: true, //nolint:gosec // intentional for pentest tooling
		}
		tlsConn := tls.Client(conn, tlsCfg)
		tlsConn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake %s: %w", addr, err)
		}
		return tlsConn, nil
	}

	return conn, nil
}

func dialThroughProxy(proxyRaw, target string, timeout time.Duration) (net.Conn, error) {
	u, err := url.Parse(proxyRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy url: %w", err)
	}
	proxyAddr := u.Host
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("proxy dial %s: %w", proxyAddr, err)
	}
	// HTTP CONNECT tunnel
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT write: %w", err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || len(line) < 12 || line[9:12] != "200" {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", line)
	}
	// drain remainder of proxy response headers
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	return conn, nil
}

// Send writes payload to conn and reads back the response up to the deadline.
// If cfg.SendDelay > 0, it pauses mid-payload at cfg.SendPauseAt bytes.
func Send(conn net.Conn, payload []byte, cfg ConnConfig) Response {
	start := time.Now()
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	deadline := start.Add(timeout)
	conn.SetDeadline(deadline) //nolint:errcheck

	var writeErr error
	if cfg.SendDelay > 0 && cfg.SendPauseAt > 0 && cfg.SendPauseAt < len(payload) {
		_, writeErr = conn.Write(payload[:cfg.SendPauseAt])
		if writeErr == nil {
			time.Sleep(cfg.SendDelay)
			conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck
			_, writeErr = conn.Write(payload[cfg.SendPauseAt:])
		}
	} else {
		_, writeErr = conn.Write(payload)
	}
	if writeErr != nil {
		return Response{Error: fmt.Errorf("write: %w", writeErr), Duration: time.Since(start)}
	}

	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	timedOut := false

	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				timedOut = true
			}
			break
		}
	}

	raw := buf.Bytes()
	resp := Response{
		Raw:      raw,
		Duration: time.Since(start),
		TimedOut: timedOut,
		Headers:  make(map[string]string),
	}
	parseResponse(&resp, raw)
	return resp
}

// SendAndReceive opens a fresh connection and sends the payload.
func SendAndReceive(cfg ConnConfig, payload []byte) Response {
	conn, err := Dial(cfg)
	if err != nil {
		return Response{Error: err}
	}
	defer conn.Close()
	return Send(conn, payload, cfg)
}

// SendPair sends two payloads over the same persistent connection.
// Used by CL.TE confirmation — first request poisons the pipe,
// second one measures whether it received a pre-poisoned response.
func SendPair(cfg ConnConfig, first, second []byte) (Response, Response) {
	conn, err := Dial(cfg)
	if err != nil {
		r := Response{Error: err}
		return r, r
	}
	defer conn.Close()

	r1 := Send(conn, first, cfg)
	if r1.Error != nil || r1.TimedOut {
		return r1, Response{}
	}

	r2 := Send(conn, second, cfg)
	return r1, r2
}

// parseResponse extracts status code and headers from a raw HTTP/1.x response.
func parseResponse(resp *Response, raw []byte) {
	if len(raw) < 12 {
		return
	}
	// status line: "HTTP/1.x NNN ..."
	line := raw
	if idx := bytes.IndexByte(raw, '\n'); idx != -1 {
		line = raw[:idx]
	}
	line = bytes.TrimSpace(line)
	if len(line) >= 12 {
		code := line[9:12]
		n := 0
		for _, c := range code {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		resp.StatusCode = n
	}

	// headers
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(raw, []byte("\n\n"))
	}
	if headerEnd != -1 {
		resp.Body = raw[headerEnd+4:]
		headerBlock := raw[:headerEnd]
		for _, hline := range bytes.Split(headerBlock, []byte("\r\n")) {
			if colon := bytes.IndexByte(hline, ':'); colon != -1 {
				k := string(bytes.TrimSpace(hline[:colon]))
				v := string(bytes.TrimSpace(hline[colon+1:]))
				resp.Headers[k] = v
			}
		}
	}
}

// TargetFromURL builds a ConnConfig from a raw URL string.
func TargetFromURL(rawURL string) (ConnConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ConnConfig{}, fmt.Errorf("parse url: %w", err)
	}
	cfg := ConnConfig{Host: u.Hostname()}
	switch u.Scheme {
	case "https":
		cfg.TLS = true
		cfg.Port = 443
	case "http":
		cfg.Port = 80
	default:
		return ConnConfig{}, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &cfg.Port) //nolint:errcheck
	}
	return cfg, nil
}
