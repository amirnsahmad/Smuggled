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
	Timeout       time.Duration
	Proxy         string
	SkipTLSVerify bool
	Verbose       bool
	Workers       int
	ConfirmReps   int

	// Methods is the list of HTTP methods to use for base requests.
	// Supports multi-value: []string{"GET","POST","HEAD"}.
	// Empty defaults to []string{"POST"}.
	Methods []string

	// ForceMethod: if true, body-bearing probes (CL.TE/TE.CL) use the
	// configured method even when bodyless (GET/HEAD). Without this flag
	// those probes silently upgrade to POST.
	ForceMethod bool

	// Feature flags — each skip disables a detection module
	SkipH2              bool
	SkipParser          bool
	SkipClientDesync    bool
	SkipPause           bool
	SkipImplicitZero    bool
	SkipConnectionState bool
	SkipCL0             bool
	SkipChunkSizes      bool
	SkipH1Tunnel        bool
	SkipH2Tunnel        bool
	SkipHeaderRemoval   bool

	TechniquesFilter []string // if non-empty, only run matching technique names
}

// DefaultConfig returns production-safe defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:     10 * time.Second,
		ConfirmReps: 3,
		Workers:     5,
		Methods:     []string{"POST"},
	}
}

// effectiveMethods returns the deduplicated, uppercased list of methods to scan.
// Falls back to ["POST"] when empty.
func effectiveMethods(cfg Config) []string {
	if len(cfg.Methods) == 0 {
		return []string{"POST"}
	}
	seen := make(map[string]bool)
	var out []string
	for _, m := range cfg.Methods {
		u := strings.ToUpper(strings.TrimSpace(m))
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return []string{"POST"}
	}
	return out
}

// effectiveMethod returns the single method to use for a probe.
// requiresBody=true: bodyless methods are upgraded to POST unless ForceMethod.
func effectiveMethod(cfg Config, requiresBody bool) string {
	methods := effectiveMethods(cfg)
	m := methods[0] // primary method
	if requiresBody && !cfg.ForceMethod {
		switch m {
		case "GET", "HEAD", "OPTIONS", "TRACE":
			return "POST"
		}
	}
	return m
}

// BuildBaseRequest builds a raw HTTP/1.1 request for method + URL.
func BuildBaseRequest(u *url.URL, cfg Config) []byte {
	return buildRequestForMethod(u, effectiveMethods(cfg)[0])
}

// buildRequestForMethod builds a raw request for a specific method.
func buildRequestForMethod(u *url.URL, method string) []byte {
	host := u.Hostname()
	if p := u.Port(); p != "" {
		host = host + ":" + p
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	hasBody := method != "GET" && method != "HEAD" && method != "OPTIONS" && method != "TRACE"

	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n")
	if hasBody {
		b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		b.WriteString("Content-Length: 3\r\n")
	}
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	if hasBody {
		b.WriteString("x=y")
	}
	return []byte(b.String())
}

// ─── Internal helpers shared across scan modules ──────────────────────────────

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

func statusCode(resp []byte) int {
	if len(resp) < 12 {
		return 0
	}
	code := 0
	fmt.Sscanf(string(resp[9:12]), "%d", &code)
	return code
}

func containsStr(resp []byte, s string) bool {
	return bytes.Contains(bytes.ToLower(resp), []byte(strings.ToLower(s)))
}

func makeChunkedBody(body string, extraLen int) string {
	sz := len(body) + extraLen
	if sz <= 0 {
		return "0\r\n\r\n"
	}
	return fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", sz, body)
}

func setBody(req []byte, body string) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(req, sep)
	if idx < 0 {
		return append(req, []byte(body)...)
	}
	result := make([]byte, idx+4+len(body))
	copy(result, req[:idx+4])
	copy(result[idx+4:], []byte(body))
	return result
}

func setContentLength(req []byte, n int) []byte {
	return permute.SetHeader(req, "Content-Length", fmt.Sprintf("%d", n))
}

func setConnection(req []byte, value string) []byte {
	return permute.SetHeader(req, "Connection", value)
}

func addTE(req []byte) []byte {
	if !bytes.Contains(bytes.ToLower(req), []byte("transfer-encoding:")) {
		return permute.SetHeader(req, "Transfer-Encoding", "chunked")
	}
	return req
}

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
	return err == nil && !timedOut && len(resp) > 0
}

func filterTechniques(all []permute.Technique, filter []string) []permute.Technique {
	if len(filter) == 0 {
		return all
	}
	set := make(map[string]bool, len(filter))
	for _, f := range filter {
		set[strings.ToLower(f)] = true
	}
	var out []permute.Technique
	for _, t := range all {
		if set[strings.ToLower(t.Name)] {
			out = append(out, t)
		}
	}
	return out
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

// Scanner orchestrates all detection modules against a single target.
type Scanner struct {
	cfg      Config
	reporter *report.Reporter
}

// New creates a Scanner.
func New(cfg Config, r *report.Reporter) *Scanner {
	return &Scanner{cfg: cfg, reporter: r}
}

// Scan runs all enabled modules against the target URL for every configured method.
func (s *Scanner) Scan(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		s.reporter.Log("invalid URL %s: %v", rawURL, err)
		return
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	if !connectivityCheck(u, s.cfg) {
		s.reporter.Log("host %s appears unresponsive, skipping", u.Host)
		return
	}

	methods := effectiveMethods(s.cfg)
	s.reporter.Progress("scanning %s [methods=%s]", u.String(), strings.Join(methods, ","))

	for _, method := range methods {
		// Build a config scoped to this single method
		methodCfg := s.cfg
		methodCfg.Methods = []string{method}

		base := buildRequestForMethod(u, method)

		s.reporter.Log("--- method=%s ---", method)
		s.runModules(u, base, methodCfg)
	}
}

// runModules fires every enabled scanner module for a given (url, base, cfg) triple.
func (s *Scanner) runModules(u *url.URL, base []byte, cfg Config) {
	rep := s.reporter

	// ── Core HTTP/1.1 desync ─────────────────────────────────────────────────
	ScanCLTE(u, base, cfg, rep)
	ScanTECL(u, base, cfg, rep)

	// ── CL.0 ────────────────────────────────────────────────────────────────
	if !cfg.SkipCL0 {
		ScanCL0(u, base, cfg, rep)
	}

	// ── Chunk-size parsing discrepancies ─────────────────────────────────────
	if !cfg.SkipChunkSizes {
		ScanChunkSizes(u, base, cfg, rep)
	}

	// ── Parser discrepancy (v3.0) ────────────────────────────────────────────
	if !cfg.SkipParser {
		ScanParserDiscrepancy(u, base, cfg, rep)
	}

	// ── Client-side desync ───────────────────────────────────────────────────
	if !cfg.SkipClientDesync {
		ScanClientDesync(u, base, cfg, rep)
	}

	// ── Connection-state + pause desync ─────────────────────────────────────
	if !cfg.SkipConnectionState {
		ScanConnectionState(u, base, cfg, rep)
	}
	if !cfg.SkipPause {
		ScanPauseDesync(u, base, cfg, rep)
	}

	// ── Implicit zero CL ─────────────────────────────────────────────────────
	if !cfg.SkipImplicitZero {
		ScanImplicitZero(u, base, cfg, rep)
	}

	// ── H1 tunnel (HEAD/method-override) ────────────────────────────────────
	if !cfg.SkipH1Tunnel {
		ScanH1Tunnel(u, base, cfg, rep)
	}

	// ── H2 downgrade, H2 tunnel, HeadScanTE ─────────────────────────────────
	if !cfg.SkipH2 {
		ScanH2Downgrade(u, base, cfg, rep)
		ScanH2Tunnel(u, base, cfg, rep)
		ScanHeadScanTE(u, base, cfg, rep)
	}

	// ── Header removal (Keep-Alive stripping) ────────────────────────────────
	if !cfg.SkipHeaderRemoval {
		ScanHeaderRemoval(u, base, cfg, rep)
	}
}
