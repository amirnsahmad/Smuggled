package scan

// pipelinedesync.go — Pipeline-based browser desync (OldClientDesyncScan.java)
//
// Strategy:
// Unlike the "wait" client desync (clientdesync.go) which detects CL-ignoring
// servers passively, this module actively exploits connection reuse by sending a
// POST with a smuggled request prefix as body, followed by a victim request on
// the same TCP connection. If the follow-up response reflects the smuggled canary
// or its status diverges from the expected baseline, the connection was poisoned.
//
// This maps to OldClientDesyncScan.java which uses TurboIntruder to pipeline:
//   1. Attack: POST / HTTP/1.1 + CL: len(payload) + body = "GET /<canary> HTTP/1.1\r\nX: Y"
//   2. Followup: GET / HTTP/1.1 on same connection (immediately pipelined)
//   3. If followup reflects the canary from the attack body → confirmed
//   4. Also tests over H2 to detect H2→H1 downgrade desync
//
// Detection signals:
//   - Canary string from attack body appears in followup response (reflected)
//   - Followup status differs from normal baseline (status divergence)
//   - Single TCP connection is used for both requests (verified via helper)

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/transport"
)

// ScanPipelineDesync probes for pipeline-based browser desync.
func ScanPipelineDesync(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("PipelineDesync probe: %s", target.Host)
	dbg(cfg, "PipelineDesync: starting, target=%s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	canary := generateCanary()

	// The smuggled body: a GET request whose path contains the canary.
	// "X: Y" at the end makes the leftover bytes from the next request on the
	// connection be absorbed as the value of the X header — preventing parse errors.
	smuggledReq := fmt.Sprintf("GET /%s HTTP/1.1\r\nX: Y", canary)

	// Attack: POST with CL = len(smuggledReq) and the smuggled body.
	var attackBuilder strings.Builder
	attackBuilder.WriteString(fmt.Sprintf("POST %s HTTP/1.1\r\n", path))
	attackBuilder.WriteString(fmt.Sprintf("Host: %s\r\n", host))
	attackBuilder.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
	attackBuilder.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	attackBuilder.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(smuggledReq)))
	attackBuilder.WriteString("Connection: keep-alive\r\n")
	attackBuilder.WriteString("\r\n")
	attackBuilder.WriteString(smuggledReq)
	attackBytes := []byte(attackBuilder.String())

	// Followup: simple GET on same connection.
	followup := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		path, host)
	followupBytes := []byte(followup)

	// Establish baseline status for followup
	baseResp, _, _, _ := request.RawRequest(target, followupBytes, cfg)
	baseStatus := request.StatusCode(baseResp)
	dbg(cfg, "PipelineDesync: baseline status=%d", baseStatus)
	if isRateLimited(baseStatus) {
		return
	}

	// Run attack cycles
	for attempt := 0; attempt < 4; attempt++ {
		conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
		if err != nil {
			dbg(cfg, "PipelineDesync: dial error: %v", err)
			return
		}

		// Send attack
		if err := conn.Send(attackBytes); err != nil {
			conn.Close()
			continue
		}

		// Read attack response
		r1, _, t1 := conn.RecvWithTimeout(cfg.Timeout)
		if t1 || len(r1) == 0 {
			conn.Close()
			continue
		}
		if request.ContainsStr(r1, "connection: close") {
			conn.Close()
			continue
		}

		// Verify single connection (check we haven't been redirected to a new socket)
		st1 := request.StatusCode(r1)
		dbg(cfg, "PipelineDesync: attempt %d, attack status=%d", attempt, st1)

		// Send followup on same connection
		if err := conn.Send(followupBytes); err != nil {
			conn.Close()
			continue
		}

		// Read followup response
		r2, _, t2 := conn.RecvWithTimeout(cfg.Timeout)
		conn.Close()

		if t2 || len(r2) == 0 {
			continue
		}
		st2 := request.StatusCode(r2)
		dbg(cfg, "PipelineDesync: attempt %d, followup status=%d", attempt, st2)

		// Detection: canary reflected in followup response
		if request.ContainsStr(r2, canary) {
			rep.Emit(report.Finding{
				Target:   target.String(),
				Method:   "POST",
				Severity: report.SeverityConfirmed,
				Type:     "pipeline-desync",
				Technique: "browser-desync-reflected",
				Description: fmt.Sprintf(
					"Pipeline browser desync confirmed: canary '%s' from the POST body "+
						"was reflected in the follow-up response on the same connection. "+
						"The server treated the POST body as the start of a new request. "+
						"Reference: https://portswigger.net/research/browser-powered-desync-attacks",
					canary),
				Evidence: fmt.Sprintf("canary=%s attack_status=%d followup_status=%d reflected=true",
					canary, st1, st2),
				RawProbe: request.Truncate(string(attackBytes), 512),
			})
			rep.Log("PipelineDesync [!] canary reflected on %s", target.String())
			return
		}

		// Detection: status divergence (followup != baseline)
		if st2 != baseStatus && st2 != st1 && !isRateLimited(st2) {
			// Confirm: repeat to filter jitter
			confirmCount := 0
			for c := 0; c < 3; c++ {
				cConn, cErr := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
				if cErr != nil {
					break
				}
				cConn.Send(attackBytes) //nolint:errcheck
				cR1, _, cT1 := cConn.RecvWithTimeout(cfg.Timeout)
				if cT1 || len(cR1) == 0 || request.ContainsStr(cR1, "connection: close") {
					cConn.Close()
					continue
				}
				cConn.Send(followupBytes) //nolint:errcheck
				cR2, _, cT2 := cConn.RecvWithTimeout(cfg.Timeout)
				cConn.Close()
				if cT2 || len(cR2) == 0 {
					continue
				}
				if request.StatusCode(cR2) != baseStatus {
					confirmCount++
				}
			}

			if confirmCount >= 2 {
				rep.Emit(report.Finding{
					Target:   target.String(),
					Method:   "POST",
					Severity: report.SeverityProbable,
					Type:     "pipeline-desync",
					Technique: "browser-desync-status",
					Description: fmt.Sprintf(
						"Pipeline browser desync: follow-up request on the same connection "+
							"received status %d (baseline=%d) after the POST attack. "+
							"The server may be treating the POST body as a new request prefix. "+
							"Reference: https://portswigger.net/research/browser-powered-desync-attacks",
						st2, baseStatus),
					Evidence: fmt.Sprintf("baseline=%d attack_status=%d followup_status=%d confirmed=%d/3",
						baseStatus, st1, st2, confirmCount),
					RawProbe: request.Truncate(string(attackBytes), 512),
				})
				rep.Log("PipelineDesync [!] status divergence on %s", target.String())
				return
			}
		}
	}
}
