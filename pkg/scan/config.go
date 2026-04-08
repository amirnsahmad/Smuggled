package scan

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

	// Module skip flags
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

	// TechniquesFilter: if non-empty only run techniques whose Name is in this list.
	TechniquesFilter []string
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
func effectiveMethods(cfg Config) []string {
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
func effectiveMethod(cfg Config, requiresBody bool) string {
	m := effectiveMethods(cfg)[0]
	if requiresBody && !cfg.ForceMethod && isBodylessMethod(m) {
		return "POST"
	}
	return m
}

// isBodylessMethod returns true for HTTP methods that do not carry a request body
// in normal usage.
func isBodylessMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	}
	return false
}
