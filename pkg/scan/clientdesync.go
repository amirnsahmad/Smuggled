package scan

// clientdesync.go — Client-side desync detection
//
// Maps to ClientDesyncScan.java (waitScan method).
//
// Strategy:
// Send a POST with Content-Length set to the length of a follow-up GET request.
// Body is intentionally empty (CL > actual body = server waits for more bytes).
// If the connection is kept alive and a second request on the same conn immediately
// gets a response, the server treated the two messages as one — classic client desync.

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/smuggled/smuggled/pkg/report"
	"github.com/smuggled/smuggled/pkg/transport"
)

// ScanClientDesync probes for browser-powered / client-side desync.
func ScanClientDesync(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	rep.Log("ClientDesync probe: %s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// The follow-up request that will be swallowed by the desync
	followup := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)

	// The crafted POST: CL = len(followup), body = "" (empty)
	// A vulnerable server will keep reading until it gets len(followup) bytes,
	// treating the actual follow-up GET as the body of this POST.
	var probe strings.Builder
	probe.WriteString("POST " + path + " HTTP/1.1\r\n")
	probe.WriteString("Host: " + host + "\r\n")
	probe.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n")
	probe.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	probe.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(followup)))
	probe.WriteString("Content-length: 0\r\n") // bypass CL normalisation (duplicate, lowercase)
	probe.WriteString("Connection: keep-alive\r\n")
	probe.WriteString("\r\n")
	// intentionally no body

	probeBytes := []byte(probe.String())
	followupBytes := []byte(followup)

	// Open a single raw connection and send both requests sequentially
	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		rep.Log("ClientDesync: dial error: %v", err)
		return
	}
	defer conn.Close()

	if err := conn.Send(probeBytes); err != nil {
		rep.Log("ClientDesync: send probe error: %v", err)
		return
	}

	// Read response to the POST — if server accepted keep-alive we should get one
	r1, elapsed1, r1TimedOut := conn.RecvWithTimeout(cfg.Timeout)
	if r1TimedOut || len(r1) == 0 {
		rep.Log("ClientDesync: no response to probe (elapsed=%v)", elapsed1)
		return
	}

	st1 := statusCode(r1)
	if st1 == 0 {
		return
	}

	// Check if connection is still alive (server sent keep-alive)
	if containsStr(r1, "connection: close") {
		rep.Log("ClientDesync: server closed connection, not vulnerable")
		return
	}

	// Send follow-up on same connection
	if err := conn.Send(followupBytes); err != nil {
		rep.Log("ClientDesync: send followup error: %v", err)
		return
	}

	shortTimeout := 3 * time.Second
	if cfg.Timeout < shortTimeout {
		shortTimeout = cfg.Timeout / 2
	}
	r2, elapsed2, r2TimedOut := conn.RecvWithTimeout(shortTimeout)
	_ = elapsed2

	if r2TimedOut || len(r2) == 0 {
		// Server is waiting for more bytes from the POST body — possible desync
		// Confirm with a normal request to see if server is still healthy
		rep.Log("ClientDesync: follow-up timed out — potential CSD signal")
		return
	}

	st2 := statusCode(r2)

	// Two valid responses on a single connection where the second came back fast
	// is the key indicator of client-side desync.
	if st1 > 0 && st2 > 0 {
		desc := fmt.Sprintf("Got two responses (%d, %d) on a single connection in %.0fms — "+
			"server may be treating next request body as a new request (client-side desync)",
			st1, st2, float64(elapsed1.Milliseconds()))

		rep.Emit(report.Finding{
			Target:      target.String(),
			Severity:    report.SeverityProbable,
			Type:        "client-desync",
			Technique:   "CL-body-smuggle",
			Description: desc,
			Evidence:    fmt.Sprintf("r1_status=%d r2_status=%d elapsed=%v", st1, st2, elapsed1),
			RawProbe:    truncate(string(probeBytes)+"\n---followup---\n"+string(followupBytes), 768),
		})
	}
}
