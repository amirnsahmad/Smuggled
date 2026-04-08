package scan

// scanner.go — top-level orchestrator.
//
// Scanner.Scan() is the single entry point: it iterates over every configured
// HTTP method, builds the base request, runs all enabled detection modules,
// and writes findings to the Reporter.

import (
	"net/url"
	"strings"

	"github.com/smuggled/smuggled/pkg/permute"
	"github.com/smuggled/smuggled/pkg/report"
)

// Scanner orchestrates all detection modules against a single target.
type Scanner struct {
	cfg Config
	rep *report.Reporter
}

// New creates a Scanner.
func New(cfg Config, rep *report.Reporter) *Scanner {
	return &Scanner{cfg: cfg, rep: rep}
}

// Scan runs all enabled modules against rawURL for every configured HTTP method.
func (s *Scanner) Scan(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		s.rep.Log("invalid URL %s: %v", rawURL, err)
		return
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	if !connectivityCheck(u, s.cfg) {
		s.rep.Log("host %s appears unresponsive, skipping", u.Host)
		return
	}

	methods := effectiveMethods(s.cfg)
	s.rep.Progress("scanning %s [methods=%s]", u.String(), strings.Join(methods, ","))

	for _, method := range methods {
		// Clone config scoped to this single method so modules always see
		// a single-element Methods list and effectiveMethods(cfg)[0] is unambiguous.
		methodCfg := s.cfg
		methodCfg.Methods = []string{method}

		base := buildRequestForMethod(u, method)
		s.rep.Log("--- method=%s ---", method)
		s.runModules(u, base, methodCfg)
	}
}

// runModules fires every enabled detection module in a defined order.
func (s *Scanner) runModules(u *url.URL, base []byte, cfg Config) {
	rep := s.rep

	// ── H/1.1 body-desync ────────────────────────────────────────────────────
	ScanCLTE(u, base, cfg, rep)
	ScanTECL(u, base, cfg, rep)

	// ── CL.0 (Content-Length zero desync) ────────────────────────────────────
	if !cfg.SkipCL0 {
		ScanCL0(u, base, cfg, rep)
	}

	// ── Chunk-size terminator discrepancies ───────────────────────────────────
	if !cfg.SkipChunkSizes {
		ScanChunkSizes(u, base, cfg, rep)
	}

	// ── Parser discrepancy (v3.0) ─────────────────────────────────────────────
	if !cfg.SkipParser {
		ScanParserDiscrepancy(u, base, cfg, rep)
	}

	// ── Client-side desync ────────────────────────────────────────────────────
	if !cfg.SkipClientDesync {
		ScanClientDesync(u, base, cfg, rep)
	}

	// ── Connection-state + pause desync ──────────────────────────────────────
	if !cfg.SkipConnState {
		ScanConnectionState(u, base, cfg, rep)
	}
	if !cfg.SkipPause {
		ScanPauseDesync(u, base, cfg, rep)
	}

	// ── Implicit zero CL (GET/HEAD with body) ─────────────────────────────────
	if !cfg.SkipImplicitZero {
		ScanImplicitZero(u, base, cfg, rep)
	}

	// ── H1 tunnel (HEAD + method-override headers) ────────────────────────────
	if !cfg.SkipH1Tunnel {
		ScanH1Tunnel(u, base, cfg, rep)
	}

	// ── H2 downgrade / tunnel / HeadScanTE ───────────────────────────────────
	if !cfg.SkipH2 {
		ScanH2Downgrade(u, base, cfg, rep)
		if !cfg.SkipH2Tunnel {
			ScanH2Tunnel(u, base, cfg, rep)
			ScanHeadScanTE(u, base, cfg, rep)
		}
	}

	// ── Keep-Alive header removal ─────────────────────────────────────────────
	if !cfg.SkipHeaderRemoval {
		ScanHeaderRemoval(u, base, cfg, rep)
	}
}

// filterTechniques returns the subset of all that are in the filter list.
// If filter is empty, all techniques are returned.
func filterTechniques(all []permute.Technique, filter []string) []permute.Technique {
	if len(filter) == 0 {
		return all
	}
	set := make(map[string]bool, len(filter))
	for _, f := range filter {
		set[strings.ToLower(f)] = true
	}
	out := make([]permute.Technique, 0, len(all))
	for _, t := range all {
		if set[strings.ToLower(t.Name)] {
			out = append(out, t)
		}
	}
	return out
}

// techniqueEnabled reports whether a named technique should run given the filter.
// Equivalent to filterTechniques for single-name checks.
func techniqueEnabled(name string, cfg Config) bool {
	if len(cfg.TechniquesFilter) == 0 {
		return true
	}
	for _, f := range cfg.TechniquesFilter {
		if strings.EqualFold(f, name) {
			return true
		}
	}
	return false
}
