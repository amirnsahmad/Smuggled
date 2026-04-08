// Package scan implements HTTP Request Smuggling detection probes.
// Each scanner operates over a raw TCP/TLS connection to avoid HTTP client normalisation.
package scan

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/smuggled/smuggled/pkg/permute"
	"github.com/smuggled/smuggled/pkg/report"
	"github.com/smuggled/smuggled/pkg/transport"
)

// Config holds per-scan configuration passed from the CLI.
type Config struct {
	Timeout     time.Duration
	Proxy       string
	SkipTLSVerify bool
	Verbose     bool
	Workers     int
	ConfirmReps int // number of repeat confirmations (default 3)

	// Feature flags
	SkipH2           bool
	SkipParser       bool
	SkipClientDesync bool
	SkipPause        bool
	SkipImplicitZero bool
	SkipConnectionState bool
	TechniquesFilter []string // if set, only run these technique names
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:     10 * time.Second,
		ConfirmReps: 3,
		Workers:     5,
	}
}

// Target bundles a parsed URL with the raw request bytes to use as base.
type Target struct {
	URL     *url.URL
	BaseReq []byte // raw HTTP/1.1 request bytes
}

// BuildBaseRequest constructs a minimal POST request for the given URL.
func BuildBaseRequest(u *url.URL) []byte {
	host := u.Hostname()
	if p := u.Port(); p != "" {
		host = host + ":" + p
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString("Content-Length: 3\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	b.WriteString("x=y")
	return []byte(b.String())
}

// rawRequest opens a fresh connection, sends raw bytes, and returns the response.
// elapsed is the time until first-byte (or timeout).
func rawRequest(target *url.URL, payload []byte, cfg Config) (resp []byte, elapsed time.Duration, timedOut bool, err error) {
	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return nil, 0, false, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if err = conn.Send(payload); err != nil {
		return nil, 0, false, fmt.Errorf("send: %w", err)
	}

	data, dur, readErr := conn.RecvWithTimeout(cfg.Timeout)
	if len(data) == 0 && readErr {
		return nil, dur, true, nil
	}
	return data, dur, false, nil
}

// statusCode extracts the HTTP status code integer from raw response bytes.
func statusCode(resp []byte) int {
	if len(resp) < 12 {
		return 0
	}
	// "HTTP/1.1 200 ..."
	code := 0
	fmt.Sscanf(string(resp[9:12]), "%d", &code)
	return code
}

// containsStr checks whether the response contains a substring (case-insensitive).
func containsStr(resp []byte, s string) bool {
	return bytes.Contains(bytes.ToLower(resp), []byte(strings.ToLower(s)))
}

// makeChunkedBody encodes body as chunked with given hex size + terminates with 0\r\n\r\n.
func makeChunkedBody(body string, extraLen int) string {
	sz := len(body) + extraLen
	if sz <= 0 {
		return "0\r\n\r\n"
	}
	return fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", sz, body)
}

// setBody replaces everything after \r\n\r\n in the request.
func setBody(req []byte, body string) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(req, sep)
	if idx < 0 {
		return append(req, []byte(body)...)
	}
	return append(req[:idx+4], []byte(body)...)
}

// setContentLength replaces the Content-Length header value.
func setContentLength(req []byte, n int) []byte {
	return permute.SetHeader(req, "Content-Length", fmt.Sprintf("%d", n))
}

// setConnection sets the Connection header.
func setConnection(req []byte, value string) []byte {
	return permute.SetHeader(req, "Connection", value)
}

// addTE adds Transfer-Encoding: chunked if not present.
func addTE(req []byte) []byte {
	if !bytes.Contains(bytes.ToLower(req), []byte("transfer-encoding:")) {
		return permute.SetHeader(req, "Transfer-Encoding", "chunked")
	}
	return req
}

// connectivityCheck sends a normal GET to verify the host is reachable.
func connectivityCheck(u *url.URL, cfg Config) bool {
	host := u.Hostname()
	if p := u.Port(); p != "" {
		host = host + ":" + p
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := []byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
	resp, _, timedOut, err := rawRequest(u, req, cfg)
	if err != nil || timedOut || len(resp) == 0 {
		return false
	}
	return true
}

// filterTechniques returns a subset of techniques if a filter is configured.
func filterTechniques(all []permute.Technique, filter []string) []permute.Technique {
	if len(filter) == 0 {
		return all
	}
	set := make(map[string]bool, len(filter))
	for _, f := range filter {
		set[f] = true
	}
	var out []permute.Technique
	for _, t := range all {
		if set[t.Name] {
			out = append(out, t)
		}
	}
	return out
}

// Scanner orchestrates all scan modules against a single target.
type Scanner struct {
	cfg      Config
	reporter *report.Reporter
}

// New creates a Scanner.
func New(cfg Config, r *report.Reporter) *Scanner {
	return &Scanner{cfg: cfg, reporter: r}
}

// Scan runs all enabled scan modules against a target URL.
func (s *Scanner) Scan(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		s.reporter.Log("invalid URL %s: %v", rawURL, err)
		return
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	s.reporter.Progress("scanning %s", u.String())

	base := BuildBaseRequest(u)

	if !connectivityCheck(u, s.cfg) {
		s.reporter.Log("host %s appears unresponsive, skipping", u.Host)
		return
	}

	// Run all modules
	ScanCLTE(u, base, s.cfg, s.reporter)
	ScanTECL(u, base, s.cfg, s.reporter)

	if !s.cfg.SkipParser {
		ScanParserDiscrepancy(u, base, s.cfg, s.reporter)
	}
	if !s.cfg.SkipClientDesync {
		ScanClientDesync(u, base, s.cfg, s.reporter)
	}
	if !s.cfg.SkipConnectionState {
		ScanConnectionState(u, base, s.cfg, s.reporter)
	}
	if !s.cfg.SkipImplicitZero {
		ScanImplicitZero(u, base, s.cfg, s.reporter)
	}
	if !s.cfg.SkipPause {
		ScanPauseDesync(u, base, s.cfg, s.reporter)
	}
	if !s.cfg.SkipH2 {
		ScanH2Downgrade(u, base, s.cfg, s.reporter)
	}
}
