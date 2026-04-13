package scan

// connstate.go — Connection state manipulation / pause-based desync
//
// Maps to ConnectionStateScan.java and PauseDesyncScan.java.
//
// Strategy A (connection state): Compare the status code returned when the same
// trigger request is sent as the 1st request on a fresh connection vs. as the 2nd
// request on a reused keep-alive connection. Servers like HAProxy switch their
// HTTP parsing state-machine after the first request, so the second request may be
// parsed differently — enabling desync. This matches statusScan() in
// ConnectionStateScan.java.
//
// Strategy B (pause desync): Send partial request data, pause, then send the rest.
// Some servers flush buffers mid-stream and can be confused by the timing gap.
// Confirmation is via canary reflection in the follow-up response, matching
// PauseDesyncScan.java.

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/transport"
)

// generateCanary returns a short random canary string.
func generateCanary() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))] //nolint:gosec
	}
	return "wrtz" + string(b)
}

// ScanConnectionState tests for connection-state-based desync.
//
// Mirrors ConnectionStateScan.statusScan():
//  1. Build a "trigger" request with a randomised canary subdomain as Host
//     (e.g. Host: <canary>.example.com). Sent directly it should return some status D.
//  2. Send a normal warm-up request on a new keep-alive connection, then immediately
//     send the trigger on the same connection.
//  3. If the trigger returns a different status than when sent directly, the server
//     is treating first vs. second requests differently → connection-state desync.
//  4. Anti-noise: confirm the difference holds for a second probe to a different path.
func ScanConnectionState(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("ConnectionState probe: %s", target.Host)
	dbg(cfg, "ConnState: starting, target=%s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	canary := generateCanary()
	canaryHost := canary + "." + target.Hostname()

	// Normal warm-up request (well-formed, valid Host)
	warmup := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nConnection: keep-alive\r\n\r\n",
		path, host)

	// Trigger: same path but with canary subdomain as Host
	trigger := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nConnection: keep-alive\r\n\r\n",
		path, canaryHost)

	// Step 1: send trigger directly (fresh connection) → get "direct" status
	connDirect, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		rep.Log("ConnectionState: dial error: %v", err)
		return
	}
	defer connDirect.Close()
	if err := connDirect.Send([]byte(trigger)); err != nil {
		return
	}
	rDirect, _, tDirect := connDirect.RecvWithTimeout(cfg.Timeout)
	if tDirect || len(rDirect) == 0 {
		return
	}
	directStatus := request.StatusCode(rDirect)

	// Step 2: warm-up + trigger on same keep-alive connection → get "indirect" status
	connKA, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return
	}
	defer connKA.Close()
	if err := connKA.Send([]byte(warmup)); err != nil {
		return
	}
	rWarmup, _, tWarmup := connKA.RecvWithTimeout(cfg.Timeout)
	if tWarmup || len(rWarmup) == 0 {
		return
	}
	if request.ContainsStr(rWarmup, "connection: close") {
		rep.Log("ConnectionState: server closed after warmup, not keep-alive capable")
		return
	}
	if err := connKA.Send([]byte(trigger)); err != nil {
		return
	}
	rIndirect, _, tIndirect := connKA.RecvWithTimeout(cfg.Timeout)
	if tIndirect || len(rIndirect) == 0 {
		return
	}
	indirectStatus := request.StatusCode(rIndirect)

	dbg(cfg, "ConnState: direct=%d indirect=%d", directStatus, indirectStatus)
	if directStatus == indirectStatus {
		return // no difference — not vulnerable
	}

	// Step 3: anti-noise check — send trigger to a different path via warmup+trigger
	// If response is still different from direct, confirms it is state-driven not random
	noisePath := "/.well-known/cake"
	noiseTrigger := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
		noisePath, canaryHost)
	connNoise, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return
	}
	defer connNoise.Close()
	connNoise.Send([]byte(warmup))              //nolint:errcheck
	rNoiseWarmup, _, _ := connNoise.RecvWithTimeout(cfg.Timeout)
	if len(rNoiseWarmup) == 0 || request.ContainsStr(rNoiseWarmup, "connection: close") {
		return
	}
	connNoise.Send([]byte(noiseTrigger)) //nolint:errcheck
	rNoise, _, _ := connNoise.RecvWithTimeout(cfg.Timeout)
	noiseStatus := request.StatusCode(rNoise)

	dbg(cfg, "ConnState: noise=%d (direct=%d)", noiseStatus, directStatus)
	if noiseStatus == directStatus {
		return
	}
	dbg(cfg, "ConnState: DETECTED status divergence direct=%d indirect=%d noise=%d", directStatus, indirectStatus, noiseStatus)

	rep.Emit(report.Finding{
		Target:    target.String(),
		Method:    config.EffectiveMethods(cfg)[0],
		Severity:  report.SeverityProbable,
		Type:      "connection-state",
		Technique: "status-diff",
		Description: fmt.Sprintf(
			"Connection-state desync: trigger request returned status %d when sent directly, "+
				"but status %d when sent as 2nd request on a reused connection. "+
				"The server parses requests differently based on connection state. "+
				"Reference: https://portswigger.net/research/browser-powered-desync-attacks",
			directStatus, indirectStatus),
		Evidence: fmt.Sprintf(
			"direct_status=%d indirect_status=%d noise_status=%d canary=%s",
			directStatus, indirectStatus, noiseStatus, canary),
		RawProbe: request.Truncate(warmup+"\n---trigger---\n"+trigger, 768),
	})
}

// ScanConnectionStateReflect detects connection-state desync via canary reflection count.
// Maps to ConnectionStateScan.reflectScan() in Java.
//
// Unlike statusScan (which compares status codes), reflectScan counts how many
// times a canary string appears in the response body when sent directly vs. as
// the 2nd request on a reused connection. If the reflection count differs, the
// server routes/processes second requests differently → connection-state desync.
func ScanConnectionStateReflect(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("ConnectionStateReflect probe: %s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	canary := generateCanary()

	// Trigger uses canary as a parameter so it may be reflected in the response
	triggerPath := fmt.Sprintf("%s?%s=1", path, canary)
	warmup := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
		path, host)
	trigger := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n",
		triggerPath, host)

	// Step 1: direct trigger → count canary reflections
	connDirect, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return
	}
	defer connDirect.Close()
	if err := connDirect.Send([]byte(trigger)); err != nil {
		return
	}
	rDirect, _, tDirect := connDirect.RecvWithTimeout(cfg.Timeout)
	if tDirect || len(rDirect) == 0 {
		return
	}
	directCount := countOccurrences(rDirect, []byte(canary))

	// Step 2: warmup + trigger on same keep-alive connection → count reflections
	connKA, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return
	}
	defer connKA.Close()
	if err := connKA.Send([]byte(warmup)); err != nil {
		return
	}
	rWarmup, _, tWarmup := connKA.RecvWithTimeout(cfg.Timeout)
	if tWarmup || len(rWarmup) == 0 {
		return
	}
	if request.ContainsStr(rWarmup, "connection: close") {
		return
	}
	if err := connKA.Send([]byte(trigger)); err != nil {
		return
	}
	rIndirect, _, tIndirect := connKA.RecvWithTimeout(cfg.Timeout)
	if tIndirect || len(rIndirect) == 0 {
		return
	}
	indirectCount := countOccurrences(rIndirect, []byte(canary))

	if directCount == indirectCount {
		return // same reflection count — not vulnerable
	}

	// Confirm: repeat to filter noise
	confirmedDiffs := 0
	for i := 0; i < 3; i++ {
		c, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
		if err != nil {
			continue
		}
		c.Send([]byte(warmup))                       //nolint:errcheck
		rw, _, tw := c.RecvWithTimeout(cfg.Timeout)
		if tw || len(rw) == 0 || request.ContainsStr(rw, "connection: close") {
			c.Close()
			continue
		}
		c.Send([]byte(trigger)) //nolint:errcheck
		ri, _, _ := c.RecvWithTimeout(cfg.Timeout)
		c.Close()
		if countOccurrences(ri, []byte(canary)) != directCount {
			confirmedDiffs++
		}
	}
	if confirmedDiffs < 2 {
		return // not consistent
	}

	rep.Emit(report.Finding{
		Target:    target.String(),
		Method:    config.EffectiveMethods(cfg)[0],
		Severity:  report.SeverityProbable,
		Type:      "connection-state",
		Technique: "reflect-diff",
		Description: fmt.Sprintf(
			"Connection-state desync (reflection): canary '%s' appeared %d times when sent directly "+
				"but %d times as 2nd request on a reused connection. "+
				"The server processes requests differently based on connection state.",
			canary, directCount, indirectCount),
		Evidence: fmt.Sprintf(
			"direct_reflections=%d indirect_reflections=%d canary=%s",
			directCount, indirectCount, canary),
		RawProbe: request.Truncate(warmup+"\n---trigger---\n"+trigger, 768),
	})
}

// countOccurrences counts non-overlapping occurrences of needle in haystack.
func countOccurrences(haystack, needle []byte) int {
	count := 0
	for i := 0; ; {
		j := bytes.Index(haystack[i:], needle)
		if j < 0 {
			break
		}
		count++
		i += j + len(needle)
	}
	return count
}

// ScanPauseDesync tests for pause-based desync (mid-request TCP pause).
//
// Mirrors PauseDesyncScan.java:
//  1. Build a POST where the body contains a smuggled GET to a poison path
//     (e.g. /favicon.ico?<poisonCanary>=1). The Content-Length covers the body.
//  2. Send headers + pause mid-body. A vulnerable front-end flushes/forwards after
//     the pause — the back-end sees the body as a new request (poison request).
//  3. Immediately send a normal follow-up GET to the original path.
//  4. If the follow-up response contains the poison canary or the poison-path content
//     (e.g. "image/"), the poison request leaked into the follow-up → confirmed.
//  5. Title follows Java: reflect / expected-response / status variants.
func ScanPauseDesync(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("PauseDesync probe: %s", target.Host)
	dbg(cfg, "PauseDesync: starting, target=%s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	pauseDuration := 6 * time.Second
	if cfg.Timeout < pauseDuration+2*time.Second {
		return // need headroom above the pause duration
	}

	poisonCanary := generateCanary()
	poisonPath := "/favicon.ico?" + poisonCanary + "=1"
	// The smuggled body is a partial GET that the back-end would parse as a new req
	// "GET /favicon.ico?<canary>=1 HTTP/1.1\r\nX: Y" — X: Y is an incomplete header
	// so the back-end will wait for more, then time out / return 400.
	smuggledBody := fmt.Sprintf("GET %s HTTP/1.1\r\nX: Y", poisonPath)

	// Base POST: CL = len(smuggledBody), body = smuggledBody
	headers := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		path, host, len(smuggledBody))

	// Follow-up request sent after the pause to detect poison bleeding in
	followup := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)

	// Baseline: send follow-up directly to see its normal response
	connBaseline, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		rep.Log("PauseDesync: dial error: %v", err)
		return
	}
	connBaseline.Send([]byte(followup)) //nolint:errcheck
	rBaseline, _, _ := connBaseline.RecvWithTimeout(cfg.Timeout)
	connBaseline.Close()
	if len(rBaseline) == 0 {
		return
	}
	baselineStatus := request.StatusCode(rBaseline)

	// Check that a poison-path canary is not already present in baseline (sanity)
	poisonExpect := []byte("ype: image/") // partial "Content-Type: image/" — matches favicon
	if request.ContainsStr(rBaseline, poisonCanary) || strings.Contains(string(rBaseline), string(poisonExpect)) {
		return // baseline already contains signals — can't distinguish
	}

	// Open a keep-alive connection, send headers, pause, then send body
	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return
	}
	defer conn.Close()

	if err := conn.Send([]byte(headers)); err != nil {
		return
	}

	// Pause before sending body
	time.Sleep(pauseDuration)

	// Check if the server already responded (some do if Connection: close is in effect)
	earlyResp, _, earlyTimeout := conn.RecvWithTimeout(500 * time.Millisecond)
	if !earlyTimeout && len(earlyResp) > 0 {
		if request.ContainsStr(earlyResp, "connection: close") {
			// Server closed after timeout — won't accept the follow-up
			rep.Log("PauseDesync: server closed on pause, skipping")
			return
		}
	}

	// Send the smuggled body
	if err := conn.Send([]byte(smuggledBody)); err != nil {
		return
	}

	r1, _, r1TimedOut := conn.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "PauseDesync: r1 status=%d len=%d timeout=%v", request.StatusCode(r1), len(r1), r1TimedOut)
	if r1TimedOut || len(r1) == 0 {
		return
	}
	if request.ContainsStr(r1, "connection: close") {
		dbg(cfg, "PauseDesync: conn closed after r1")
		return
	}

	if err := conn.Send([]byte(followup)); err != nil {
		return
	}
	r2, _, _ := conn.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "PauseDesync: r2 status=%d len=%d", request.StatusCode(r2), len(r2))
	if len(r2) == 0 {
		return
	}

	// Determine which desync title applies (mirrors Java logic)
	var title string
	switch {
	case request.ContainsStr(r2, poisonCanary):
		title = "Pause-based desync - reflect"
	case strings.Contains(string(r2), string(poisonExpect)):
		title = "Pause-based desync - expected-response"
	case request.StatusCode(r2) != baselineStatus &&
		!request.ContainsStr(r2, poisonCanary):
		title = "Pause-based desync - status"
	default:
		return // no signal
	}

	rep.Emit(report.Finding{
		Target:    target.String(),
		Method:    config.EffectiveMethods(cfg)[0],
		Severity:  report.SeverityProbable,
		Type:      "pause-desync",
		Technique: "pause-body-smuggle",
		Description: title + ": " +
			"The website appears vulnerable to a pause-based desync. " +
			"A POST request with a mid-body TCP pause caused the follow-up response " +
			"to contain evidence of the smuggled request. " +
			"Reference: https://portswigger.net/research/browser-powered-desync-attacks",
		Evidence: fmt.Sprintf(
			"baseline_status=%d r1_status=%d r2_status=%d poison_canary=%s",
			baselineStatus, request.StatusCode(r1), request.StatusCode(r2), poisonCanary),
		RawProbe: request.Truncate(headers+smuggledBody+"\n---followup---\n"+followup, 768),
	})
}
