package scan

// tecl.go — TE.CL desync detection.
//
// Strategy (ChunkContentScan.java TE.CL path):
//   Front-end obeys Transfer-Encoding; back-end obeys Content-Length.
//
//   Probe body:  "3\r\nx=y\r\n0\r\n\r\n"  (13 bytes — exact chunked body)
//   CL: 14  (bodyLen + 1 — one MORE byte than what the front-end will forward)
//   'X' appended AFTER the complete request bytes (after CL is already set)
//
//   TE.CL server:
//     Front-end (TE): terminates at 0\r\n\r\n, forwards only 13 bytes of body.
//     'X' stays in the front-end's input buffer and is NOT forwarded.
//     Back-end (CL=14): expects 14 bytes but receives 13 → TIMEOUT ✓
//
//   Non-TE.CL server:
//     Front-end (CL=14): forwards all 14 bytes (including 'X').
//     Back-end receives CL=14, 14 bytes → responds normally ✓
//
//   This mirrors ChunkContentScan.java:
//     makeChunked(original, +1, 0, config, false) → CL = bodyLen+1
//     then: reverseLengthBuilder.write('X') appended after full request bytes
//
// bypassCLFix lowercases "Content-Length" → "Content-length" to prevent some
// middleware from normalising the header (mirrors bypassContentLengthFix in Java).

import (
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"fmt"
	"net/url"

	"github.com/smuggled/smuggled/internal/permute"
	"github.com/smuggled/smuggled/internal/report"
)

// ScanTECL iterates all H1 TE permutations looking for a TE.CL desync signal.
func ScanTECL(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	workingBase, probeMethod := request.UpgradeToBodyMethod(base, cfg, rep.Log)
	configuredMethod := config.EffectiveMethods(cfg)[0]
	dbg(cfg, "TE.CL: starting scan, method=%s target=%s", probeMethod, target.Host)

	syncedBody := "0\r\n\r\n"
	syncedReq := request.SetContentLength(request.SetBody(
		request.AddTE(request.SetConnection(workingBase, "close")),
		syncedBody), len(syncedBody))
	_, _, syncedTimedOut, syncedErr := request.RawRequest(target, syncedReq, cfg)
	if syncedErr != nil || syncedTimedOut {
		rep.Log("TE.CL: synced baseline timed out or errored for %s, skipping TE.CL scan", target.Host)
		dbg(cfg, "TE.CL: synced baseline failed (err=%v timeout=%v)", syncedErr, syncedTimedOut)
		return
	}

	// Probe body: exact chunked body with correct chunk + terminator.
	// CL = bodyLen + 1 so the back-end (CL) waits for one more byte than what
	// the front-end (TE) actually forwards.
	// 'X' is appended to the end of each probe request AFTER CL is set.
	const teClBody = "3\r\nx=y\r\n0\r\n\r\n" // 13 bytes — exact chunked body (no malformedClose)

	// Add Transfer-Encoding: chunked to the base BEFORE applying TE permutations.
	// Same reason as ScanCLTE: ApplyTE techniques replace/modify an existing TE header.
	// Without this, all replacement-based techniques return nil and are skipped.
	baseWithTE := request.AddTE(workingBase)
	baseWithTE = request.SetConnection(baseWithTE, "close")

	for _, tech := range filterTechniques(permute.H1Techniques(), cfg.TechniquesFilter) {
		if tech.H2Only {
			continue
		}

		mutated := permute.ApplyTE(baseWithTE, tech.Name)
		if mutated == nil {
			continue
		}
		// Do NOT call AddTE here — TE was already added to baseWithTE above.

		// Per-technique sanity check (mirrors ChunkContentScan.syncedBreakReq):
		// Send the same TE permutation with CL = exact body length. If this times
		// out the technique itself breaks the server — skip to avoid false positives.
		syncedBreakReq := request.BypassCLFix(request.SetContentLength(request.SetBody(mutated, teClBody), len(teClBody)))
		_, _, syncedBreakTimedOut, _ := request.RawRequest(target, syncedBreakReq, cfg)
		if syncedBreakTimedOut {
			rep.Log("TE.CL: technique %s causes timeout even with exact CL, skipping (FP guard)", tech.Name)
			dbg(cfg, "TE.CL [%s] syncedBreak TIMEOUT — FP, skip", tech.Name)
			continue
		}
		dbg(cfg, "TE.CL [%s] syncedBreak OK", tech.Name)

		// CL = len(teClBody) + 1 = 14.  'X' appended after the complete request so
		// front-end (TE) terminates at 0\r\n\r\n and does NOT forward 'X'; back-end
		// (CL=14) expects 14 bytes but only receives 13 → TIMEOUT.
		probeReq := request.BypassCLFix(request.SetContentLength(request.SetBody(mutated, teClBody), len(teClBody)+1))
		probeReq = append(probeReq, 'X')

		rep.Log("TE.CL probe: technique=%s method=%s target=%s cl=%d", tech.Name, probeMethod, target.Host, len(teClBody)+1)

		resp, probeElapsed, timedOut, err := request.RawRequest(target, probeReq, cfg)
		if err != nil {
			rep.Log("TE.CL send error (%s): %v", tech.Name, err)
			continue
		}

		delayed := cfg.IsDelayed(probeElapsed)
		dbg(cfg, "TE.CL [%s] PROBE → timeout=%v delayed=%v suspicious=%v status=%d elapsed=%v",
			tech.Name, timedOut, delayed, request.IsSuspiciousResponse(resp), request.StatusCode(resp), probeElapsed)

		if timedOut || delayed || request.IsSuspiciousResponse(resp) {
			confirmed := request.ConfirmProbe(target, probeReq, cfg, rep.Log, "TE.CL")
			sev := report.SeverityProbable
			if confirmed {
				sev = report.SeverityConfirmed
			}
			desc := "Front-end uses Transfer-Encoding; back-end uses Content-Length."
			if probeMethod != configuredMethod {
				desc += fmt.Sprintf(" Probe sent as %s (upgraded from %s — TE.CL requires a body).", probeMethod, configuredMethod)
			}
			evidence := fmt.Sprintf("timeout=%v delayed=%v (elapsed=%v threshold=%v) suspicious=%v confirmed=%v",
				timedOut, delayed, probeElapsed, cfg.DelayThreshold, request.IsSuspiciousResponse(resp), confirmed)
			rep.Emit(report.Finding{
				Target:      target.String(),
				Method:      probeMethod,
				Severity:    sev,
				Type:        "TE.CL",
				Technique:   tech.Name,
				Description: desc,
				Evidence:    evidence,
				RawProbe:    request.Truncate(string(probeReq), 512),
				RawResponse: request.Truncate(request.SanitizeResponse(resp), 512),
			})
			if cfg.ExitOnFind {
				return
			}
			// Without -x/--exit: continue testing remaining techniques
		}
	}
}
