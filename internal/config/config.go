package config

// config.go — scan configuration and method resolution.

import (
	"strings"
	"time"
)

// Config holds all parameters for a scan run.
type Config struct {
	// Connection
	Timeout       time.Duration
	Proxy         string
	SkipTLSVerify bool

	// Output
	Verbose bool
	// Debug controls the verbosity of low-level tracing written to stderr.
	//   0 = off
	//   1 = first request line + response status/elapsed (--debug)
	//   2 = full raw request and response bytes (--debug 2)
	Debug int

	// DebugLog is called by RawRequest with the raw bytes of every probe sent
	// and response received. Set by the CLI when --debug is active.
	// Using a callback avoids an import cycle between request ↔ report.
	DebugLog func(format string, args ...any)

	// Concurrency
	Workers     int
	ConfirmReps int // confirmations required before promoting to CONFIRMED

	// Methods: list of HTTP methods to probe (e.g. ["POST"], ["GET","POST","HEAD"]).
	// Empty → defaults to ["POST"].
	Methods []string

	// ForceMethod: when true, body-bearing probes (CL.TE, TE.CL) honour Methods[0]
	// even if it is bodyless (GET/HEAD). Without this flag those probes silently
	// upgrade to POST and log the upgrade.
	ForceMethod bool

	// Protocol scope: when both are false the behaviour is "both enabled".
	// Set ScanHTTP1=true to restrict to H1-only scanners.
	// Set ScanHTTP2=true to restrict to H2-only scanners.
	// Both can be true simultaneously (same as default).
	ScanHTTP1 bool
	ScanHTTP2 bool

	// Module skip flags
	SkipCLTE          bool
	SkipTECL          bool
	SkipH2            bool
	SkipParser        bool
	SkipClientDesync  bool
	SkipPause         bool
	SkipImplicitZero  bool
	SkipConnState     bool
	SkipCL0           bool
	SkipChunkSizes    bool
	SkipH1Tunnel      bool
	SkipH2Tunnel      bool
	SkipHeaderRemoval bool
	SkipPathCRLF      bool

	// Modules: if non-empty, only run modules whose name is in this list.
	// Names: clte, tecl, cl0, chunksizes, parser, client-desync, conn-state,
	// pause, implicit-zero, h1-tunnel, header-removal, h2, h2-tunnel, h2-research,
	// path-crlf.
	// When set, all skip flags are ignored — only listed modules run.
	Modules []string

	// ResearchMode enables experimental probes (HTTP2FakePseudo, HTTP2Scheme,
	// HTTP2DualPath, HTTP2Method, HiddenHTTP2). Off by default.
	ResearchMode bool

	// TechniquesFilter: if non-empty only run techniques whose Name is in this list.
	TechniquesFilter []string

	// ExitOnFind: when true, CL.TE and TE.CL scanners stop after the first
	// finding (original behaviour). When false (default), they continue
	// testing ALL techniques even after a finding, which is useful for
	// debugging and full coverage assessment.
	ExitOnFind bool

	// Calibrate: when true, the scanner sends baseline requests before
	// scanning to measure normal response time, then uses
	// median + CalibrationFloor as the delay threshold for ALL timing-based
	// modules. This detects "delayed responses" that aren't hard timeouts
	// but are anomalously slow compared to the baseline.
	Calibrate        bool
	CalibrationFloor time.Duration // added to median baseline (default 3s)

	// BaselineMedian is populated at runtime by the calibration phase.
	// Modules read this to compute their delay thresholds.
	// Zero means calibration was not run (use hard timeout only).
	BaselineMedian    time.Duration
	DelayThreshold    time.Duration // = BaselineMedian + CalibrationFloor

	// Attempts controls how many attack+probe cycles are sent by pipeline-poisoning
	// modules before giving up. Higher values increase detection rate on targets
	// with large connection pools, at the cost of more requests sent.
	// Applies to: ScanCL0, ScanH2CL0, h2CLSmuggle, ScanH2CLInject.
	// Default: 5.
	Attempts int

	// CanaryPath is the URL path used in smuggled requests for poisoning
	// detection (H2.CL, CL.0, etc.). Defaults to DefaultCanaryPath.
	// Useful when the target has WAF rules or routing that filters common paths.
	CanaryPath string

	// ExtraHeaders are injected into every outgoing request (both H1 and H2).
	// Populated from -H / --header flags. Format: "Name: Value".
	// Used to pass auth tokens, session cookies, custom headers, etc.
	ExtraHeaders []string

	// Cookies holds session cookies captured from the initial probe response
	// (Set-Cookie headers) or passed explicitly via -H "Cookie: ...".
	// Injected as a single "Cookie: k=v; k2=v2" header on all requests.
	Cookies string
}

// DefaultCanaryPath is the canary path used when --canary-path is not set.
const DefaultCanaryPath = "/smuggled-canary-xzyw"

// EffectiveCanaryPath returns CanaryPath if set, otherwise DefaultCanaryPath.
func EffectiveCanaryPath(cfg Config) string {
	if cfg.CanaryPath != "" {
		return cfg.CanaryPath
	}
	return DefaultCanaryPath
}


// WithDebugScope returns a copy of c whose DebugLog prefixes every message
// with "[scope] ". Scopes stack: calling WithDebugScope("B") on a cfg that was
// already WithDebugScope("A") produces messages prefixed "[A] [B] ".
// If DebugLog is nil the copy is unchanged.
func (c Config) WithDebugScope(scope string) Config {
	if c.DebugLog == nil {
		return c
	}
	parent := c.DebugLog
	c.DebugLog = func(format string, args ...any) {
		parent("["+scope+"] "+format, args...)
	}
	return c
}

// IsDelayed returns true when elapsed exceeds the calibrated delay threshold.
// Returns false if calibration was not run (DelayThreshold == 0).
func (c Config) IsDelayed(elapsed time.Duration) bool {
	return c.DelayThreshold > 0 && elapsed > c.DelayThreshold
}

// DefaultCalibrationFloor is added to the baseline median when --calibrate is used.
const DefaultCalibrationFloor = 3 * time.Second

// ModuleEnabled returns true if the named module should run.
// When Modules is non-empty it acts as an allowlist (skip flags ignored).
// When Modules is empty it falls back to the skip flag for the module.
func (c Config) ModuleEnabled(name string, skipFlag bool) bool {
	if len(c.Modules) > 0 {
		for _, m := range c.Modules {
			if strings.EqualFold(m, name) {
				return true
			}
		}
		return false
	}
	return !skipFlag
}

// DefaultConfig returns safe, conservative defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:     10 * time.Second,
		ConfirmReps: 3,
		Workers:     5,
		Methods:     []string{"POST"},
	}
}

// effectiveMethods returns the deduplicated, uppercased method list.
// Always returns at least ["POST"].
func EffectiveMethods(cfg Config) []string {
	if len(cfg.Methods) == 0 {
		return []string{"POST"}
	}
	seen := make(map[string]bool, len(cfg.Methods))
	out := make([]string, 0, len(cfg.Methods))
	for _, m := range cfg.Methods {
		if u := strings.ToUpper(strings.TrimSpace(m)); u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	if len(out) == 0 {
		return []string{"POST"}
	}
	return out
}

// effectiveMethod returns the single method to use for one probe.
//
// requiresBody=true: if the configured method is bodyless (GET/HEAD/OPTIONS/TRACE)
// and ForceMethod is not set, returns "POST" instead and the caller should log
// the upgrade.
func EffectiveMethod(cfg Config, requiresBody bool) string {
	m := EffectiveMethods(cfg)[0]
	if requiresBody && !cfg.ForceMethod && IsBodylessMethod(m) {
		return "POST"
	}
	return m
}

// isBodylessMethod returns true for HTTP methods that do not carry a request body
// in normal usage.
func IsBodylessMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}
