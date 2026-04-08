// Package scan contains the detection engines for HTTP request smuggling variants.
// Each scanner is an independent strategy that takes a target URL and a base
// request template, fires calibrated probes via raw TCP/TLS, and returns Findings.
package scan

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"time"

	"smuggled.tool/pkg/transport"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// Severity classifies how confident we are in a finding.
type Severity string

const (
	SeverityConfirmed = Severity("CONFIRMED")
	SeverityProbable  = Severity("PROBABLE")
	SeverityInfo      = Severity("INFO")
)

// Finding describes a single detected vulnerability.
type Finding struct {
	URL         string
	Technique   string
	Type        string // e.g. "CL.TE", "TE.CL", "parser-discrepancy", "client-desync"
	Severity    Severity
	Description string
	Evidence    string
	Timestamp   time.Time
}

// Options controls scan behaviour.
type Options struct {
	// Timeout per individual probe request.
	Timeout time.Duration
	// ConfirmRounds is how many times a positive probe must repeat before
	// being reported as CONFIRMED (anti-FP).
	ConfirmRounds int
	// Workers controls parallelism when scanning technique permutations.
	Workers int
	// Verbose enables per-probe logging.
	Verbose bool
	// ProxyURL optional CONNECT proxy.
	ProxyURL string
	// SkipH2 disables HTTP/2 downgrade checks.
	SkipH2 bool
	// SkipParser disables the parser-discrepancy scan (v3.0).
	SkipParser bool
	// SkipClientDesync disables client-side desync detection.
	SkipClientDesync bool
	// SkipPause disables pause-based desync detection.
	SkipPause bool
	// OnlyTechniques limits which technique names to attempt (empty = all).
	OnlyTechniques []string
}

// DefaultOptions returns production-safe defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:       15 * time.Second,
		ConfirmRounds: 3,
		Workers:       5,
		Verbose:       false,
	}
}

// Target holds the parsed connection parameters and base request for a scan.
type Target struct {
	RawURL string
	Conn   transport.ConnConfig
	Path   string
	Host   string
	Method string
}

// ParseTarget builds a Target from a raw URL.
func ParseTarget(rawURL string) (Target, error) {
	cfg, err := transport.TargetFromURL(rawURL)
	if err != nil {
		return Target{}, err
	}
	u, _ := url.Parse(rawURL)
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	return Target{
		RawURL: rawURL,
		Conn:   cfg,
		Path:   path,
		Host:   cfg.Host,
		Method: "POST",
	}, nil
}

// BuildBaseRequest constructs a minimal POST request to the target.
func BuildBaseRequest(t Target) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\n", t.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", t.Host)
	b.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.44 Safari/537.36\r\n")
	b.WriteString("Accept: */*\r\n")
	b.WriteString("Accept-Encoding: gzip, deflate\r\n")
	b.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	return b.Bytes()
}

// ConnectivityCheck fires a simple GET to verify the target is reachable.
// Returns false if the target times out or errors.
func ConnectivityCheck(t Target, opts Options) bool {
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", t.Path)
	fmt.Fprintf(&b, "Host: %s\r\n", t.Host)
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")

	cfg := t.Conn
	cfg.Timeout = opts.Timeout
	cfg.ProxyURL = opts.ProxyURL

	resp := transport.SendAndReceive(cfg, b.Bytes())
	if resp.Error != nil || resp.TimedOut || resp.StatusCode == 0 {
		return false
	}
	return true
}

// ─── Scanner orchestrator ─────────────────────────────────────────────────────

// Scanner runs all enabled detection modules against a target.
type Scanner struct {
	opts Options
}

// New creates a Scanner with the given options.
func New(opts Options) *Scanner {
	return &Scanner{opts: opts}
}

// Scan runs all detection modules against the target URL and returns all findings.
func (s *Scanner) Scan(rawURL string) ([]Finding, error) {
	t, err := ParseTarget(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}

	if !ConnectivityCheck(t, s.opts) {
		return nil, fmt.Errorf("target %s appears unreachable (timeout/error on baseline GET)", t.Host)
	}

	base := BuildBaseRequest(t)
	var all []Finding

	// CL.TE
	if s.opts.Verbose {
		logf("Running CL.TE scan against %s", t.Host)
	}
	all = append(all, ScanCLTE(t, base, s.opts)...)

	// TE.CL
	if s.opts.Verbose {
		logf("Running TE.CL scan against %s", t.Host)
	}
	all = append(all, ScanTECL(t, base, s.opts)...)

	// Parser Discrepancy (v3.0)
	if !s.opts.SkipParser {
		if s.opts.Verbose {
			logf("Running parser-discrepancy scan against %s", t.Host)
		}
		all = append(all, ScanParserDiscrepancy(t, base, s.opts)...)
	}

	// Client-side desync
	if !s.opts.SkipClientDesync {
		if s.opts.Verbose {
			logf("Running client-desync scan against %s", t.Host)
		}
		all = append(all, ScanClientDesync(t, base, s.opts)...)
	}

	// Implicit zero Content-Length
	if s.opts.Verbose {
		logf("Running implicit-zero CL scan against %s", t.Host)
	}
	all = append(all, ScanImplicitZero(t, base, s.opts)...)

	// Pause-based desync
	if !s.opts.SkipPause {
		if s.opts.Verbose {
			logf("Running pause-desync scan against %s", t.Host)
		}
		all = append(all, ScanPauseDesync(t, base, s.opts)...)
	}

	// H2 downgrade
	if !s.opts.SkipH2 {
		if s.opts.Verbose {
			logf("Running H2-downgrade scan against %s", t.Host)
		}
		all = append(all, ScanH2Downgrade(t, base, s.opts)...)
	}

	return all, nil
}

// ─── Helpers shared across scan modules ──────────────────────────────────────

func logf(format string, args ...any) {
	fmt.Printf("[smuggled] "+format+"\n", args...)
}

// responseContains checks whether the raw response bytes contain a string.
func responseContains(resp transport.Response, s string) bool {
	return bytes.Contains(resp.Raw, []byte(s))
}

// statusClass returns the HTTP status class (2 = 2xx, 4 = 4xx, etc.)
func statusClass(code int) int { return code / 100 }

// isTimeout returns true if the response represents a genuine network timeout.
func isTimeout(resp transport.Response) bool { return resp.TimedOut && resp.StatusCode == 0 }

// confirm fires the same probe n times and checks that all produce a consistent result.
// Returns true only if all n probes match the expected condition.
func confirm(n int, probe func() bool) bool {
	for i := 0; i < n; i++ {
		if !probe() {
			return false
		}
	}
	return true
}

// techniqueEnabled returns true if the technique is in the OnlyTechniques whitelist
// (or the whitelist is empty, meaning all are enabled).
func techniqueEnabled(name string, opts Options) bool {
	if len(opts.OnlyTechniques) == 0 {
		return true
	}
	for _, t := range opts.OnlyTechniques {
		if strings.EqualFold(t, name) {
			return true
		}
	}
	return false
}
