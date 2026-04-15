package scan

// clientdesync.go — Client-side desync detection
//
// Maps to ClientDesyncScan.java (waitScan method).
//
// Strategy:
// Send a POST with a large Content-Length but NO body. If the server responds
// immediately (without waiting for the declared body bytes), it is ignoring
// Content-Length. A CL-ignoring server is vulnerable to client-side desync:
// a browser can send a POST whose body bytes are treated by the server as the
// start of the next request, poisoning the connection for other users.
//
// Detection probes (matching ClientDesyncScan.java):
//
//  1. HTTP/2 POST — Content-Length: 280, no body.
//     H2 servers don't use CL for framing (DATA frames do), but they may forward
//     CL to the H1 back-end. If the back-end ignores CL, it responds immediately.
//
//  2. HTTP/1.1 POST — Content-Length: 170, no body.
//     Confirmation probe: if the server also ignores CL over H1, a browser-based
//     attack is directly exploitable without H2.
//
// Both probes use the same detection heuristic:
//   elapsed << cfg.Timeout → server did not wait for the body → CL ignored.
//
// An additional dual-CL probe is run for cases where the server doesn't outright
// ignore CL but prefers a second (lower) CL value — the follow-up request is then
// swallowed as the POST body (back-end picks large CL, front-end strips it).

import (
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/transport"
)

// csdProbeH2CL is the Content-Length used in the H2 client desync probe.
// Matches ClientDesyncScan.java's waitScan H2 probe.
const csdProbeH2CL = 280

// csdProbeH1CL is the Content-Length used in the H1 client desync probe.
// Matches ClientDesyncScan.java's waitScan H1 probe.
const csdProbeH1CL = 170

// ScanClientDesync probes for client-side (browser-powered) desync.
func ScanClientDesync(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("ClientDesync probe: %s", target.Host)
	dbg(cfg, "ClientDesync: starting, target=%s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// timeoutThreshold: if elapsed < this, server responded without waiting for body.
	// Using the same ratio as other timeout-based detections.
	timeoutThreshold := time.Duration(float64(cfg.Timeout) * request.TimeoutRatio)

	// ── Probe 1: HTTP/2 — immediate response with large CL, no body ──────────
	if target.Scheme == "https" && request.ProbeH2(target, cfg) {
		dbg(cfg, "ClientDesync: H2 probe CL=%d", csdProbeH2CL)

		start := time.Now()
		extra := map[string]string{
			"content-length": fmt.Sprintf("%d", csdProbeH2CL),
		}
		// Send empty body — h2RawRequest with body="" will suppress CL automatically,
		// but we override it explicitly to force CL=280 even with no DATA payload.
		h2resp, h2err := h2RawRequest(target, "POST", path, host, "", extra, cfg)
		h2elapsed := time.Since(start)

		dbg(cfg, "ClientDesync: H2 elapsed=%v threshold=%v err=%v", h2elapsed, timeoutThreshold, h2err)

		if h2err == nil && h2resp != nil && h2resp.Status != 0 && h2elapsed < timeoutThreshold {
			probe := fmt.Sprintf("POST %s HTTP/2\r\nHost: %s\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: %d\r\n\r\n",
				path, host, csdProbeH2CL)
			rep.Emit(report.Finding{
				Target:    target.String(),
				Method:    "HTTP/2",
				Severity:  report.SeverityProbable,
				Type:      "client-desync",
				Technique: "wait-h2",
				Description: fmt.Sprintf(
					"Client-side desync: H2 POST with Content-Length: %d and no body "+
						"received a response in %v (threshold=%v). The server responded "+
						"immediately without waiting for the declared body bytes, indicating "+
						"Content-Length is being ignored. This makes the server susceptible to "+
						"browser-powered request smuggling.",
					csdProbeH2CL, h2elapsed.Round(time.Millisecond), timeoutThreshold),
				Evidence: fmt.Sprintf("h2_elapsed=%v status=%d cl=%d body_sent=0",
					h2elapsed.Round(time.Millisecond), h2resp.Status, csdProbeH2CL),
				RawProbe: probe,
			})
			if cfg.ExitOnFind {
				return
			}
		}
	}

	// ── Probe 2: HTTP/1.1 — immediate response with large CL, no body ────────
	{
		dbg(cfg, "ClientDesync: H1 probe CL=%d", csdProbeH1CL)

		var h1probe strings.Builder
		h1probe.WriteString("POST " + path + " HTTP/1.1\r\n")
		h1probe.WriteString("Host: " + host + "\r\n")
		h1probe.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n")
		h1probe.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		h1probe.WriteString(fmt.Sprintf("Content-Length: %d\r\n", csdProbeH1CL))
		h1probe.WriteString("Connection: close\r\n")
		h1probe.WriteString("\r\n")
		// intentionally no body

		h1probeBytes := []byte(h1probe.String())

		resp, elapsed, timedOut, err := request.RawRequest(target, h1probeBytes, cfg)
		dbg(cfg, "ClientDesync: H1 elapsed=%v timedOut=%v status=%d err=%v",
			elapsed, timedOut, request.StatusCode(resp), err)

		if err == nil && !timedOut && len(resp) > 0 && elapsed < timeoutThreshold {
			st := request.StatusCode(resp)
			if st > 0 {
				rep.Emit(report.Finding{
					Target:    target.String(),
					Method:    "POST",
					Severity:  report.SeverityProbable,
					Type:      "client-desync",
					Technique: "wait-h1",
					Description: fmt.Sprintf(
						"Client-side desync: HTTP/1.1 POST with Content-Length: %d and no body "+
							"received a %d response in %v (threshold=%v). The server responded "+
							"without waiting for the declared body bytes — Content-Length is being "+
							"ignored, enabling browser-powered request smuggling.",
						csdProbeH1CL, st, elapsed.Round(time.Millisecond), timeoutThreshold),
					Evidence: fmt.Sprintf("h1_elapsed=%v status=%d cl=%d body_sent=0",
						elapsed.Round(time.Millisecond), st, csdProbeH1CL),
					RawProbe: request.Truncate(string(h1probeBytes), 512),
				})
				if cfg.ExitOnFind {
					return
				}
			}
		}
	}

	// ── Probe 3: dual-CL swallow — back-end prefers large CL over front-end's ──
	//
	// A different class of vulnerability: the server uses TWO Content-Length headers.
	// The front-end picks the smaller one (Content-length: 0, lowercase) and reads no
	// body. The back-end picks the larger one and reads the follow-up request as body,
	// swallowing it. If the follow-up never gets a response → the back-end consumed it.
	scanClientDesyncDualCL(target, path, host, cfg, rep)
}

// scanClientDesyncDualCL sends a dual-CL probe (CL=large + Content-length: 0) and
// checks if a follow-up request on the same keep-alive connection is swallowed.
func scanClientDesyncDualCL(target *url.URL, path, host string, cfg config.Config, rep *report.Reporter) {
	dbg(cfg, "ClientDesync: dual-CL probe")

	followup := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)

	var probe strings.Builder
	probe.WriteString("POST " + path + " HTTP/1.1\r\n")
	probe.WriteString("Host: " + host + "\r\n")
	probe.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n")
	probe.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	probe.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(followup)))
	probe.WriteString("Content-length: 0\r\n") // lowercase bypass — front-end picks this
	probe.WriteString("Connection: keep-alive\r\n")
	probe.WriteString("\r\n")

	probeBytes := []byte(probe.String())
	followupBytes := []byte(followup)

	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		rep.Log("ClientDesync: dual-CL dial error: %v", err)
		return
	}
	defer conn.Close()

	if err := conn.Send(probeBytes); err != nil {
		rep.Log("ClientDesync: dual-CL send error: %v", err)
		return
	}

	r1, elapsed1, r1TimedOut := conn.RecvWithTimeout(cfg.Timeout)
	st1 := request.StatusCode(r1)
	dbg(cfg, "ClientDesync: dual-CL r1 status=%d elapsed=%v timeout=%v", st1, elapsed1, r1TimedOut)
	if r1TimedOut || len(r1) == 0 || st1 == 0 {
		return
	}
	if request.ContainsStr(r1, "connection: close") {
		dbg(cfg, "ClientDesync: dual-CL server closed connection")
		return
	}

	if err := conn.Send(followupBytes); err != nil {
		return
	}

	shortTimeout := 3 * time.Second
	if cfg.Timeout < shortTimeout {
		shortTimeout = cfg.Timeout / 2
	}
	r2, elapsed2, r2TimedOut := conn.RecvWithTimeout(shortTimeout)
	dbg(cfg, "ClientDesync: dual-CL r2 status=%d elapsed=%v timeout=%v",
		request.StatusCode(r2), elapsed2, r2TimedOut)

	if r2TimedOut || len(r2) == 0 {
		rep.Emit(report.Finding{
			Target:    target.String(),
			Method:    config.EffectiveMethods(cfg)[0],
			Severity:  report.SeverityProbable,
			Type:      "client-desync",
			Technique: "dual-CL-swallow",
			Description: fmt.Sprintf(
				"Follow-up request on same keep-alive connection timed out after POST response "+
					"(r1_status=%d, r1_elapsed=%v). The back-end chose Content-Length: %d "+
					"(large) over Content-length: 0 (lowercase bypass), consuming the "+
					"follow-up GET as POST body — client-side desync via dual-CL.",
				st1, elapsed1, len(followup)),
			Evidence:    fmt.Sprintf("r1_status=%d r2_elapsed=%v r2_timeout=true", st1, elapsed2),
			RawProbe:    request.Truncate(string(probeBytes)+"\n---followup---\n"+string(followup), 768),
		})
	}
}
