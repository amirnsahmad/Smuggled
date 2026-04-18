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
	dbg(cfg, "ConnState → [direct] trigger (%d bytes):\n%s", len(trigger), trigger)
	if err := connDirect.Send([]byte(trigger)); err != nil {
		return
	}
	rDirect, elDirect, tDirect := connDirect.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ConnState ← [direct] status=%d len=%d elapsed=%v timedOut=%v",
		request.StatusCode(rDirect), len(rDirect), elDirect, tDirect)
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
	dbg(cfg, "ConnState → [warmup] (%d bytes):\n%s", len(warmup), warmup)
	if err := connKA.Send([]byte(warmup)); err != nil {
		return
	}
	rWarmup, elWarmup, tWarmup := connKA.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ConnState ← [warmup] status=%d len=%d elapsed=%v timedOut=%v",
		request.StatusCode(rWarmup), len(rWarmup), elWarmup, tWarmup)
	if tWarmup || len(rWarmup) == 0 {
		return
	}
	if request.ContainsStr(rWarmup, "connection: close") {
		rep.Log("ConnectionState: server closed after warmup, not keep-alive capable")
		return
	}
	dbg(cfg, "ConnState → [indirect] trigger (%d bytes):\n%s", len(trigger), trigger)
	if err := connKA.Send([]byte(trigger)); err != nil {
		return
	}
	rIndirect, elIndirect, tIndirect := connKA.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ConnState ← [indirect] status=%d len=%d elapsed=%v timedOut=%v",
		request.StatusCode(rIndirect), len(rIndirect), elIndirect, tIndirect)
	if tIndirect || len(rIndirect) == 0 {
		return
	}
	indirectStatus := request.StatusCode(rIndirect)

	dbg(cfg, "ConnState: direct=%d indirect=%d", directStatus, indirectStatus)
	if isRateLimited(directStatus) || isRateLimited(indirectStatus) {
		rep.Log("ConnectionState: rate-limited response (direct=%d indirect=%d), skipping", directStatus, indirectStatus)
		return
	}
	if directStatus == indirectStatus {
		return // no difference — not vulnerable
	}

	// Step 3: path-specificity noise check — mirrors Java statusScan():
	// Send warmup + trigger-to-/.well-known/cake on a fresh keep-alive connection.
	//
	// Key logic (from ConnectionStateScan.java lines 187-195):
	//   if indirect404code == indirectCode → return null (noise)
	//
	// Rationale: if the canary host gives the SAME non-direct status on ANY path
	// when it is the 2nd request, the difference is driven purely by host routing
	// (e.g. virtual-host mismatch always returns 421/400) rather than by connection
	// state. Only if the alternate path produces a DIFFERENT status than the original
	// indirect status does the signal become path-specific — i.e. the server's state
	// machine treats specific paths differently on reused connections → genuine desync.
	noisePath := "/.well-known/cake"
	noiseTrigger := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
		noisePath, canaryHost)
	connNoise, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return
	}
	defer connNoise.Close()
	dbg(cfg, "ConnState → [noise warmup] (%d bytes):\n%s", len(warmup), warmup)
	if err := connNoise.Send([]byte(warmup)); err != nil {
		return
	}
	rNoiseWarmup, elNoiseWarmup, tNoiseWarmup := connNoise.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ConnState ← [noise warmup] status=%d len=%d elapsed=%v timedOut=%v",
		request.StatusCode(rNoiseWarmup), len(rNoiseWarmup), elNoiseWarmup, tNoiseWarmup)
	if tNoiseWarmup || len(rNoiseWarmup) == 0 || request.ContainsStr(rNoiseWarmup, "connection: close") {
		return
	}
	dbg(cfg, "ConnState → [noise trigger] (%d bytes):\n%s", len(noiseTrigger), noiseTrigger)
	if err := connNoise.Send([]byte(noiseTrigger)); err != nil {
		return
	}
	rNoise, elNoise, _ := connNoise.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ConnState ← [noise trigger] status=%d len=%d elapsed=%v",
		request.StatusCode(rNoise), len(rNoise), elNoise)
	noiseCakeStatus := request.StatusCode(rNoise)

	dbg(cfg, "ConnState: noiseCake=%d indirect=%d direct=%d", noiseCakeStatus, indirectStatus, directStatus)

	// Java: if indirect404code == indirectCode → noise (host-uniform behavior) → bail
	if noiseCakeStatus == indirectStatus {
		dbg(cfg, "ConnState: indirect status is path-uniform → host-routing noise, skipping")
		return
	}
	dbg(cfg, "ConnState: DETECTED path-specific state divergence direct=%d indirect=%d noiseCake=%d",
		directStatus, indirectStatus, noiseCakeStatus)

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
			"direct_status=%d indirect_status=%d noise_cake_status=%d canary=%s",
			directStatus, indirectStatus, noiseCakeStatus, canary),
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
	dbg(cfg, "ConnStateReflect → [direct] trigger (%d bytes):\n%s", len(trigger), trigger)
	if err := connDirect.Send([]byte(trigger)); err != nil {
		return
	}
	rDirect, elDirect, tDirect := connDirect.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ConnStateReflect ← [direct] status=%d len=%d elapsed=%v timedOut=%v",
		request.StatusCode(rDirect), len(rDirect), elDirect, tDirect)
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
	dbg(cfg, "ConnStateReflect → [warmup] (%d bytes):\n%s", len(warmup), warmup)
	if err := connKA.Send([]byte(warmup)); err != nil {
		return
	}
	rWarmup, elWarmup, tWarmup := connKA.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ConnStateReflect ← [warmup] status=%d len=%d elapsed=%v timedOut=%v",
		request.StatusCode(rWarmup), len(rWarmup), elWarmup, tWarmup)
	if tWarmup || len(rWarmup) == 0 {
		return
	}
	if request.ContainsStr(rWarmup, "connection: close") {
		return
	}
	dbg(cfg, "ConnStateReflect → [indirect] trigger (%d bytes):\n%s", len(trigger), trigger)
	if err := connKA.Send([]byte(trigger)); err != nil {
		return
	}
	rIndirect, elIndirect, tIndirect := connKA.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ConnStateReflect ← [indirect] status=%d len=%d elapsed=%v timedOut=%v",
		request.StatusCode(rIndirect), len(rIndirect), elIndirect, tIndirect)
	if tIndirect || len(rIndirect) == 0 {
		return
	}
	indirectCount := countOccurrences(rIndirect, []byte(canary))

	if isRateLimited(request.StatusCode(rDirect)) || isRateLimited(request.StatusCode(rIndirect)) {
		return
	}
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
// Mirrors PauseDesyncScan.java (waitScan / pauseScan logic).
//
// Mechanism (Varnish synth, Apache Redirect, etc.):
//   Some servers respond to a partial HTTP request after their own request-timeout
//   fires, but leave the TCP connection open for reuse even though they only read the
//   headers off the socket. When the client then sends the body, the server treats
//   those bytes as the start of the next request — a pause-based desync.
//
// Detection flow:
//  1. Baseline: normal GET → record status for comparison.
//  2. Send only the POST headers (CL = len(smuggledBody)) — NO body yet.
//  3. Wait silently for up to (cfg.Timeout - margin). If the server responds
//     BEFORE we send any body, its own request-timeout fired → primary signal.
//     If the server does NOT respond before our timeout → not vulnerable (or our
//     timeout is too low; raise --timeout above the server's request-timeout).
//  4. Confirm: send the smuggled body bytes on the same connection. If the server
//     already left the connection half-open, these bytes are parsed as a new request.
//  5. Read r1 (response to the "new request") and check for poison signals:
//     reflect / expected-response / status-change — mirrors Java title logic.
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

	// pauseWait: how long we wait for the server to respond before we send any body.
	// Must be < cfg.Timeout so we still have budget left to send the body and read r1.
	// Detection only works when cfg.Timeout > server's request-timeout.
	const pauseMargin = 2 * time.Second
	pauseWait := cfg.Timeout - pauseMargin
	if pauseWait <= 0 {
		rep.Log("PauseDesync: cfg.Timeout (%v) too low to leave pause headroom; skipping", cfg.Timeout)
		return
	}

	// Canary path — a URL that should produce a distinctive response (e.g. 404)
	// so we can recognise if the server processed our smuggled body as a new request.
	poisonCanary := generateCanary()
	poisonPath := config.EffectiveCanaryPath(cfg)
	if poisonPath == "/" {
		poisonPath = "/favicon.ico?" + poisonCanary + "=1"
	}

	// The smuggled body: a complete GET to the canary path.
	// Sent on a connection whose headers were already processed → server parses
	// this as the next independent HTTP/1.1 request.
	smuggledBody := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		poisonPath, host)

	// Headers-only POST: CL = len(smuggledBody), NO body sent initially.
	// keep-alive so the connection stays open after the server's timeout response.
	headers := fmt.Sprintf(
		"POST %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		path, host, len(smuggledBody))

	// Baseline: direct GET to the original path — records the normal status code.
	normalGET := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	connBaseline, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		rep.Log("PauseDesync: baseline dial error: %v", err)
		return
	}
	dbg(cfg, "PauseDesync → [baseline] (%d bytes):\n%s", len(normalGET), normalGET)
	connBaseline.Send([]byte(normalGET)) //nolint:errcheck
	rBaseline, elBaseline, _ := connBaseline.RecvWithTimeout(cfg.Timeout)
	connBaseline.Close()
	dbg(cfg, "PauseDesync ← [baseline] status=%d len=%d elapsed=%v",
		request.StatusCode(rBaseline), len(rBaseline), elBaseline)
	if len(rBaseline) == 0 {
		return
	}
	baselineStatus := request.StatusCode(rBaseline)
	dbg(cfg, "PauseDesync: baseline status=%d", baselineStatus)

	// Sanity: baseline must not already reflect the canary (would be a false positive)
	if request.ContainsStr(rBaseline, poisonCanary) {
		return
	}

	// ── Step 2: send headers only, then wait for early server response ────────
	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return
	}
	defer conn.Close()

	dbg(cfg, "PauseDesync → [headers-only] (%d bytes):\n%s", len(headers), headers)
	if err := conn.Send([]byte(headers)); err != nil {
		return
	}

	// PRIMARY GATE: wait up to pauseWait for server to respond WITHOUT us sending body.
	// If the server's request-timeout fires, it sends a response and (on vulnerable
	// servers) leaves the connection open with the socket buffer at "start of new req".
	// If we time out here (earlyTimedOut=true), the server is still waiting for the
	// body → not vulnerable with current cfg.Timeout setting → bail out.
	earlyResp, earlyElapsed, earlyTimedOut := conn.RecvWithTimeout(pauseWait)

	dbg(cfg, "PauseDesync: pause wait=%v elapsed=%v timedOut=%v earlyStatus=%d earlyLen=%d",
		pauseWait, earlyElapsed, earlyTimedOut, request.StatusCode(earlyResp), len(earlyResp))

	if earlyTimedOut || len(earlyResp) == 0 {
		// Server did not respond before we sent any body — it is still waiting.
		// Raise --timeout above the server's request-timeout to detect this.
		rep.Log("PauseDesync: no early response after %v — server still waiting for body "+
			"(raise --timeout > server request-timeout to detect)", pauseWait)
		return
	}

	earlyStatus := request.StatusCode(earlyResp)
	dbg(cfg, "PauseDesync: *** EARLY RESPONSE in %v (status=%d) — server's timeout fired! ***",
		earlyElapsed.Round(time.Millisecond), earlyStatus)

	// If the server explicitly closed the connection we can't reuse it for body injection.
	if request.ContainsStr(earlyResp, "connection: close") {
		// Emit a lower-confidence finding: server timed out but closed the connection.
		// A browser-based attacker could still race the connection close, but we can't
		// confirm the body-as-new-request on this connection.
		rep.Emit(report.Finding{
			Target:    target.String(),
			Method:    config.EffectiveMethods(cfg)[0],
			Severity:  report.SeverityInfo,
			Type:      "pause-desync",
			Technique: "pause-early-close",
			Description: fmt.Sprintf(
				"Pause-based desync (partial): server responded in %v to a POST with "+
					"Content-Length: %d and no body (status=%d), but sent Connection: close. "+
					"The server's request-timeout fired before receiving the body. "+
					"A browser-powered attacker may be able to race the connection close window. "+
					"Reference: https://portswigger.net/research/browser-powered-desync-attacks",
				earlyElapsed.Round(time.Millisecond), len(smuggledBody), earlyStatus),
			Evidence: fmt.Sprintf("early_elapsed=%v early_status=%d connection_close=true",
				earlyElapsed.Round(time.Millisecond), earlyStatus),
			RawProbe: request.Truncate(headers, 512),
		})
		return
	}

	// ── Step 4: send smuggled body — treated as new request on poisoned connection ─
	dbg(cfg, "PauseDesync → [smuggled body] (%d bytes):\n%s", len(smuggledBody), smuggledBody)
	if err := conn.Send([]byte(smuggledBody)); err != nil {
		return
	}

	// r1: response to the smuggled body parsed as a new HTTP request.
	remainingTimeout := cfg.Timeout - earlyElapsed
	if remainingTimeout < time.Second {
		remainingTimeout = time.Second
	}
	r1, elR1, r1TimedOut := conn.RecvWithTimeout(remainingTimeout)
	r1Status := request.StatusCode(r1)
	dbg(cfg, "PauseDesync ← [r1] status=%d len=%d elapsed=%v timedOut=%v", r1Status, len(r1), elR1, r1TimedOut)

	// Determine signal type (mirrors Java: reflect / expected-response / status)
	poisonExpect := "image/" // favicon content-type signal
	var technique, desc string
	switch {
	case request.ContainsStr(r1, poisonCanary):
		technique = "pause-reflect"
		desc = fmt.Sprintf("Pause-based desync - reflect: canary '%s' found in response to smuggled body (treated as new request). ", poisonCanary)
	case strings.Contains(strings.ToLower(string(r1)), poisonExpect):
		technique = "pause-expected-response"
		desc = "Pause-based desync - expected-response: favicon content-type detected in response to smuggled body (treated as new request). "
	case r1Status > 0 && r1Status != baselineStatus:
		technique = "pause-status"
		desc = fmt.Sprintf("Pause-based desync - status: smuggled body produced status %d (baseline=%d). ", r1Status, baselineStatus)
	case r1TimedOut || (len(r1) == 0 && !r1TimedOut):
		// No response to the body-as-request — server may have processed it silently
		// or the connection closed. Emit a lower-confidence finding.
		technique = "pause-no-r1"
		desc = "Pause-based desync: server responded to headers-only POST before body was sent (request-timeout), then produced no response to the body bytes (possible blind desync). "
	default:
		// r1 arrived but matches baseline — inconclusive
		dbg(cfg, "PauseDesync: r1 matches baseline, no signal")
		return
	}

	rep.Emit(report.Finding{
		Target:    target.String(),
		Method:    config.EffectiveMethods(cfg)[0],
		Severity:  report.SeverityProbable,
		Type:      "pause-desync",
		Technique: technique,
		Description: desc +
			"The server responded to a POST before the body was sent (its request-timeout fired), " +
			"then treated the body bytes as a new request — classic pause-based desync. " +
			"Reference: https://portswigger.net/research/browser-powered-desync-attacks",
		Evidence: fmt.Sprintf(
			"early_elapsed=%v early_status=%d r1_status=%d baseline_status=%d canary=%s",
			earlyElapsed.Round(time.Millisecond), earlyStatus, r1Status, baselineStatus, poisonCanary),
		RawProbe: request.Truncate(headers+"\n--- (pause) ---\n"+smuggledBody, 768),
	})
}
