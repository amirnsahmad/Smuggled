package scan

// contamination.go — HEAD body contamination detection (ContaminationTest.java)
//
// Strategy:
// Send a HEAD request with a short body (e.g. "G") on a keep-alive connection.
// Per RFC 9110 §9.3.2, HEAD responses MUST NOT contain a message body, so many
// servers simply don't read the request body for HEAD requests. However, the
// unread body bytes remain in the TCP socket buffer. When the server reuses the
// connection for the next request, those leftover bytes ("G") are interpreted as
// the start of a new HTTP/1.1 request — causing connection contamination.
//
// Detection flow (mirrors ContaminationTest.java):
//  1. Baseline: establish a "clean" connection, send N identical HEAD requests.
//     All must return the same status code (stability check).
//  2. Attack: send HEAD with body="G" (1 byte). The server should respond to HEAD
//     without consuming the body byte.
//  3. Probe: send a normal HEAD immediately after on the same connection.
//     If the probe returns a DIFFERENT status than baseline → contamination.
//  4. Confirm: repeat steps 1-3 multiple times; verify the instability is
//     reproducible and not just server jitter.
//  5. Final check: re-establish stability (send N clean requests, all match
//     baseline). If the server is still unstable → noise, not vulnerability.
//
// This detects a specific class of CL.0 desync that only manifests with HEAD.

import (
	"fmt"
	"net/url"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/transport"
)

// contaminationStabilityCount is how many consecutive same-status responses
// are required before the connection is considered "stable".
const contaminationStabilityCount = 5

// contaminationConfirmCount is how many attack cycles must trigger a status
// change before reporting.
const contaminationConfirmCount = 3

// ScanContamination probes for HEAD body contamination (connection poisoning).
func ScanContamination(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("Contamination probe: %s", target.Host)
	dbg(cfg, "Contamination: starting, target=%s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// Harmless request: HEAD with no body
	harmless := fmt.Sprintf(
		"HEAD %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		path, host)

	// Attack request: HEAD with Content-Length: 1 and body "G"
	// The "G" byte stays in the TCP buffer if the server doesn't read it.
	attack := fmt.Sprintf(
		"HEAD %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: 1\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"G",
		path, host)

	// Step 1: Stability check — establish baseline status on a clean connection
	baseStatus, stable := contaminationCheckStability(target, []byte(harmless), contaminationStabilityCount, cfg)
	if !stable {
		dbg(cfg, "Contamination: server is unstable without any attack, skipping")
		return
	}
	dbg(cfg, "Contamination: baseline stable, status=%d", baseStatus)

	// Step 2: Attack loop — send attack, then probe, check for status change
	confirmed := 0
	for i := 0; i < 10 && confirmed < contaminationConfirmCount; i++ {
		conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
		if err != nil {
			dbg(cfg, "Contamination: dial error: %v", err)
			return
		}

		// Clean the connection first (send one harmless request)
		if err := conn.Send([]byte(harmless)); err != nil {
			conn.Close()
			continue
		}
		rClean, _, tClean := conn.RecvWithTimeout(cfg.Timeout)
		if tClean || len(rClean) == 0 {
			conn.Close()
			continue
		}
		if request.ContainsStr(rClean, "connection: close") {
			conn.Close()
			dbg(cfg, "Contamination: server doesn't support keep-alive, skipping")
			return
		}

		// Send attack (HEAD + body "G")
		if err := conn.Send([]byte(attack)); err != nil {
			conn.Close()
			continue
		}
		rAttack, _, tAttack := conn.RecvWithTimeout(cfg.Timeout)
		if tAttack || len(rAttack) == 0 {
			conn.Close()
			continue
		}
		if request.ContainsStr(rAttack, "connection: close") {
			conn.Close()
			continue
		}

		// Probe: send harmless immediately after on same connection
		if err := conn.Send([]byte(harmless)); err != nil {
			conn.Close()
			continue
		}
		rProbe, _, tProbe := conn.RecvWithTimeout(cfg.Timeout)
		conn.Close()

		if tProbe || len(rProbe) == 0 {
			// Timeout on probe could indicate the server consumed "G" as start of
			// next request and is now waiting for more data → strong signal
			confirmed++
			dbg(cfg, "Contamination: probe timed out (attack %d) — contamination signal", i)
			continue
		}

		probeStatus := request.StatusCode(rProbe)
		dbg(cfg, "Contamination: attack %d probeStatus=%d baseStatus=%d", i, probeStatus, baseStatus)

		if probeStatus != baseStatus {
			// Check for WAF/rate-limiting
			if isRateLimited(probeStatus) {
				dbg(cfg, "Contamination: rate-limited, skipping")
				return
			}
			confirmed++
		}
	}

	if confirmed < contaminationConfirmCount {
		dbg(cfg, "Contamination: insufficient confirmations (%d/%d)", confirmed, contaminationConfirmCount)
		return
	}

	// Step 3: Final stability check — verify server is stable again without attack.
	// If it's STILL unstable, the initial signal was noise.
	_, stableAfter := contaminationCheckStability(target, []byte(harmless), contaminationStabilityCount*4, cfg)
	if !stableAfter {
		dbg(cfg, "Contamination: server still unstable after attack — noise, not vulnerability")
		return
	}

	rep.Emit(report.Finding{
		Target:   target.String(),
		Method:   "HEAD",
		Severity: report.SeverityConfirmed,
		Type:     "contamination",
		Technique: "HEAD-body-contamination",
		Description: fmt.Sprintf(
			"HEAD body contamination: server responded to HEAD without consuming the request body. "+
				"Subsequent requests on the same connection received status changes (baseline=%d). "+
				"The unread body byte 'G' is interpreted as the start of a new request, "+
				"poisoning the connection. "+
				"Reference: https://portswigger.net/research/browser-powered-desync-attacks",
			baseStatus),
		Evidence: fmt.Sprintf("baseline_status=%d confirmed_contaminations=%d", baseStatus, confirmed),
		RawProbe: request.Truncate(attack, 512),
	})
	rep.Log("Contamination [!] HEAD body contamination confirmed on %s", target.String())
}

// contaminationCheckStability opens a fresh connection and sends `count` identical
// requests, checking that all return the same status code. Returns the common
// status and whether the check passed.
func contaminationCheckStability(target *url.URL, req []byte, count int, cfg config.Config) (int, bool) {
	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return 0, false
	}
	defer conn.Close()

	var expectedStatus int
	for i := 0; i < count; i++ {
		if err := conn.Send(req); err != nil {
			return 0, false
		}
		resp, _, timedOut := conn.RecvWithTimeout(cfg.Timeout)
		if timedOut || len(resp) == 0 {
			return 0, false
		}
		if request.ContainsStr(resp, "connection: close") {
			// Server closed: can't do keep-alive stability check
			return 0, false
		}
		st := request.StatusCode(resp)
		if i == 0 {
			expectedStatus = st
		} else if st != expectedStatus {
			return 0, false
		}
	}
	return expectedStatus, true
}
