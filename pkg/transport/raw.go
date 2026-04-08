// Package transport provides raw TCP/TLS socket connections for HTTP smuggling probes.
// The stdlib http.Client normalises headers and cannot be used for desync payloads.
package transport

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

// Conn wraps a raw net.Conn with read/write helpers.
type Conn struct {
	conn    net.Conn
	Timeout time.Duration
}

// Dial opens a raw TCP (or TLS) connection to host:port.
// proxy is optional — supports http:// and socks5:// schemes.
func Dial(target *url.URL, timeout time.Duration, proxy string, skipVerify bool) (*Conn, error) {
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	var raw net.Conn
	var err error

	if proxy != "" {
		raw, err = dialViaProxy(addr, proxy, timeout)
	} else {
		raw, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	if target.Scheme == "https" {
		tlsCfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipVerify, //nolint:gosec // intentional for pentest
		}
		tlsConn := tls.Client(raw, tlsCfg)
		if err = tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			raw.Close()
			return nil, err
		}
		if err = tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		raw = tlsConn
	}

	return &Conn{conn: raw, Timeout: timeout}, nil
}

// Send writes raw bytes directly to the connection, bypassing any HTTP normalisation.
func (c *Conn) Send(data []byte) error {
	c.conn.SetWriteDeadline(time.Now().Add(c.Timeout)) //nolint:errcheck
	_, err := c.conn.Write(data)
	return err
}

// RecvAll reads until the connection closes or times out, returning the raw response bytes.
func (c *Conn) RecvAll() ([]byte, time.Duration, error) {
	c.conn.SetReadDeadline(time.Now().Add(c.Timeout)) //nolint:errcheck
	start := time.Now()
	data, err := io.ReadAll(c.conn)
	elapsed := time.Since(start)
	if err != nil {
		// A deadline exceeded after we got data is fine — treat as success
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() && len(data) > 0 {
			return data, elapsed, nil
		}
		return data, elapsed, err
	}
	return data, elapsed, nil
}

// RecvWithTimeout reads for at most `d` and returns whatever arrived.
func (c *Conn) RecvWithTimeout(d time.Duration) ([]byte, time.Duration, bool) {
	c.conn.SetReadDeadline(time.Now().Add(d)) //nolint:errcheck
	start := time.Now()
	buf := make([]byte, 65536)
	n, err := c.conn.Read(buf)
	elapsed := time.Since(start)
	timedOut := false
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			timedOut = true
		}
	}
	return buf[:n], elapsed, timedOut
}

// Close closes the underlying connection.
func (c *Conn) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// dialViaProxy connects to addr through an HTTP CONNECT or SOCKS5 proxy.
func dialViaProxy(addr, proxy string, timeout time.Duration) (net.Conn, error) {
	pu, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	proxyAddr := pu.Host

	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("proxy dial %s: %w", proxyAddr, err)
	}

	switch pu.Scheme {
	case "http", "https":
		// HTTP CONNECT tunnel
		connect := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		if _, err = conn.Write([]byte(connect)); err != nil {
			conn.Close()
			return nil, err
		}
		buf := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(timeout)) //nolint:errcheck
		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT read: %w", err)
		}
		resp := string(buf[:n])
		if len(resp) < 12 || resp[9:12] != "200" {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT rejected: %s", resp[:min(len(resp), 64)])
		}
		return conn, nil
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported proxy scheme: %s", pu.Scheme)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
