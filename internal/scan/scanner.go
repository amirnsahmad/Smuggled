package scan

// scanner.go — top-level orchestrator.
//
// Scanner.Scan() is the single entry point: it iterates over every configured
// HTTP method, builds the base request, runs all enabled detection modules,
// and writes findings to the Reporter.

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/request"

	"github.com/smuggled/smuggled/internal/permute"
	"github.com/smuggled/smuggled/internal/report"
)

// Scanner orchestrates all detection modules against a single target.
type Scanner struct {
	cfg config.Config
	rep *report.Reporter
}

// New creates a Scanner.
func New(cfg config.Config, rep *report.Reporter) *Scanner {
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

	if !request.ConnectivityCheck(u, s.cfg) {
		s.rep.Log("host %s appears unresponsive, skipping", u.Host)
		return
	}

	// ── Protocol capability probe ────────────────────────────────────────────
	// Determine which HTTP versions the target actually supports and intersect
	// with what the user requested via --http1 / --http2.
	// When neither flag is set, both versions are attempted.
	wantH1 := !s.cfg.ScanHTTP2 || s.cfg.ScanHTTP1 // true unless user said --http2 only
	wantH2 := !s.cfg.ScanHTTP1 || s.cfg.ScanHTTP2 // true unless user said --http1 only

	hasH1 := request.ProbeH1(u, s.cfg)
	hasH2 := request.ProbeH2(u, s.cfg)

	runH1 := wantH1 && hasH1
	runH2 := wantH2 && hasH2

	if !hasH1 {
		s.rep.Progress("HTTP/1.1 not available on %s — skipping H1 scanners", u.Host)
	}
	if !hasH2 {
		s.rep.Progress("HTTP/2 not available on %s — skipping H2 scanners", u.Host)
	}
	if !runH1 && !runH2 {
		s.rep.Progress("no supported protocol to scan on %s, skipping", u.Host)
		return
	}

	// ── Cookie capture ───────────────────────────────────────────────────────
	// Send a probe GET and collect any Set-Cookie headers. Captured cookies
	// are merged into cfg.Cookies so all subsequent requests carry them.
	// Skipped if the user already provided a Cookie header via -H.
	if !hasCookieHeader(s.cfg) {
		probeReq := []byte("GET " + request.RequestPath(u) + " HTTP/1.1\r\nHost: " + request.HostHeader(u) + "\r\nConnection: close\r\n\r\n")
		probeReq = request.InjectExtraHeaders(probeReq, s.cfg)
		if probeResp, _, _, err := request.RawRequest(u, probeReq, s.cfg); err == nil && len(probeResp) > 0 {
			if cookies := request.ParseSetCookies(probeResp); cookies != "" {
				s.rep.Progress("captured cookies from probe: %s", cookies)
				s.cfg.Cookies = cookies
			}
		}
	}

	// ── Calibration phase ────────────────────────────────────────────────────
	// When --calibrate is active, send baseline requests to measure the
	// target's normal response time. The median + floor becomes the delay
	// threshold for ALL timing-based detection modules.
	if s.cfg.Calibrate {
		s.cfg = calibrate(u, s.cfg, s.rep)
	}

	methods := config.EffectiveMethods(s.cfg)
	s.rep.Progress("scanning %s [methods=%s h1=%v h2=%v]", u.String(), strings.Join(methods, ","), runH1, runH2)

	for _, method := range methods {
		// Clone config scoped to this single method so modules always see
		// a single-element Methods list and config.EffectiveMethods(cfg)[0] is unambiguous.
		methodCfg := s.cfg
		methodCfg.Methods = []string{method}

		base := request.BuildRequestForMethod(u, method)
		s.rep.Log("--- method=%s ---", method)
		s.runModules(u, base, methodCfg, runH1, runH2)
	}
}

// runModules fires every enabled detection module in a defined order.
// runH1 / runH2 reflect protocol availability + user intent; each module
// is only executed when its target protocol is available.
// When cfg.ExitOnFind is true, each module stops internally after its first
// finding but all remaining modules still run (skip within, not across).
func (s *Scanner) runModules(u *url.URL, base []byte, cfg config.Config, runH1, runH2 bool) {
	rep := s.rep
	dbg(cfg, "runModules: h1=%v h2=%v skipH2=%v skipParser=%v skipCL0=%v skipChunk=%v skipClient=%v skipConn=%v skipPause=%v skipImplicit=%v skipH1Tunnel=%v skipH2Tunnel=%v skipHeader=%v research=%v",
		runH1, runH2, cfg.SkipH2, cfg.SkipParser, cfg.SkipCL0, cfg.SkipChunkSizes, cfg.SkipClientDesync, cfg.SkipConnState, cfg.SkipPause, cfg.SkipImplicitZero, cfg.SkipH1Tunnel, cfg.SkipH2Tunnel, cfg.SkipHeaderRemoval, cfg.ResearchMode)

	if runH1 || runH2 {
		if cfg.ModuleEnabled("path-crlf", cfg.SkipPathCRLF) {
			ScanPathCRLFInject(u, base, cfg, rep)
		}
	}

	if runH1 {
		if cfg.ModuleEnabled("clte", cfg.SkipCLTE) {
			ScanCLTE(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("tecl", cfg.SkipTECL) {
			ScanTECL(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("cl0", cfg.SkipCL0) {
			ScanCL0(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("chunksizes", cfg.SkipChunkSizes) {
			ScanChunkSizes(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("parser", cfg.SkipParser) {
			ScanParserDiscrepancy(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("client-desync", cfg.SkipClientDesync) {
			ScanClientDesync(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("conn-state", cfg.SkipConnState) {
			ScanConnectionState(u, base, cfg, rep)
			ScanConnectionStateReflect(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("pause", cfg.SkipPause) {
			ScanPauseDesync(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("implicit-zero", cfg.SkipImplicitZero) {
			ScanImplicitZero(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("h1-tunnel", cfg.SkipH1Tunnel) {
			ScanH1Tunnel(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("header-removal", cfg.SkipHeaderRemoval) {
			ScanHeaderRemoval(u, base, cfg, rep)
		}
	}

	if runH2 {
		if cfg.ModuleEnabled("h2", cfg.SkipH2) {
			ScanH2Downgrade(u, base, cfg, rep)
			ScanH2CLInject(u, base, cfg, rep)
			ScanH2HeaderNameInject(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("cl0", cfg.SkipCL0) {
			ScanH2CL0(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("h2-tunnel", cfg.SkipH2Tunnel) {
			ScanH2Tunnel(u, base, cfg, rep)
			ScanH2TunnelCL(u, base, cfg, rep)
			ScanHeadScanTE(u, base, cfg, rep)
		}
		if cfg.ModuleEnabled("h2-research", !cfg.ResearchMode) {
			ScanH2Research(u, base, cfg, rep)
		}
	}
}

// calibrate sends baseline requests to measure normal response time and
// populates cfg.BaselineMedian and cfg.DelayThreshold.
func calibrate(u *url.URL, cfg config.Config, rep *report.Reporter) config.Config {
	const rounds = 5
	req := request.BuildBaseRequest(u, cfg)

	var durations []time.Duration
	for i := 0; i < rounds; i++ {
		_, elapsed, timedOut, err := request.RawRequest(u, req, cfg)
		if err != nil || timedOut {
			dbg(cfg, "calibrate: round %d failed (err=%v timeout=%v)", i, err, timedOut)
			continue
		}
		durations = append(durations, elapsed)
		dbg(cfg, "calibrate: round %d elapsed=%v", i, elapsed)
	}

	if len(durations) < 3 {
		rep.Log("calibration: only %d/%d successful responses — disabling adaptive timing", len(durations), rounds)
		return cfg
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	median := durations[len(durations)/2]
	threshold := median + cfg.CalibrationFloor

	cfg.BaselineMedian = median
	cfg.DelayThreshold = threshold

	rep.Progress("calibrated: median=%v floor=%v threshold=%v (%d samples)",
		median, cfg.CalibrationFloor, threshold, len(durations))
	dbg(cfg, "calibrate: all durations=%v", durations)

	return cfg
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

// hasCookieHeader returns true if the user already provided a Cookie header
// via -H, so automatic cookie capture can be skipped.
func hasCookieHeader(cfg config.Config) bool {
	for _, h := range cfg.ExtraHeaders {
		if len(h) >= 7 && strings.EqualFold(h[:6], "cookie") && h[6] == ':' {
			return true
		}
	}
	return cfg.Cookies != ""
}

// techniqueEnabled reports whether a named technique should run given the filter.
// Equivalent to filterTechniques for single-name checks.
func techniqueEnabled(name string, cfg config.Config) bool {
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
