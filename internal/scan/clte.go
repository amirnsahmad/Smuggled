package scan

// clte.go — CL.TE desync detection.
//
// Strategy (ChunkContentScan.java, CL.TE path):
//   Front-end obeys Content-Length; back-end obeys Transfer-Encoding.
//
//   Probe body: "3\r\nx=y\r\n1\r\nZ\r\nQ\r\n\r\n"
//     — two chunks (one real, one malformed) so CL truncation lands mid-chunk.
//   CL = bodyLen - 6  (6 bytes short of the end)
//
//   CL.TE server:
//     Front-end (uses CL) forwards only (bodyLen-6) bytes — stops mid-chunk.
//     Back-end (uses TE) waits for the rest of the chunk → TIMEOUT ✓
//
//   Non-CL.TE server:
//     Front-end (uses TE) forwards the complete body.
//     Back-end reads CL bytes, responds → no timeout ✓
//
//   Per-technique sanity check (mirrors ChunkContentScan.syncedBreakReq):
//     Same body with CL = full bodyLen.  If THIS times out, the technique
//     itself breaks the server and we skip to avoid false positives.
//
// Confirmation: repeat cfg.ConfirmReps times, require consistent signal.

import (
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"fmt"
	"net/url"

	"github.com/smuggled/smuggled/internal/permute"
	"github.com/smuggled/smuggled/internal/report"
)

// ScanCLTE iterates all H1 TE permutations looking for a CL.TE desync signal.
func ScanCLTE(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	workingBase, probeMethod := request.UpgradeToBodyMethod(base, cfg, rep.Log)
	configuredMethod := config.EffectiveMethods(cfg)[0]
	dbg(cfg, "CL.TE: starting scan, method=%s target=%s", probeMethod, target.Host)

	syncedBody := "0\r\n\r\n"
	syncedReq := request.SetContentLength(request.SetBody(
		request.AddTE(request.SetConnection(workingBase, "close")),
		syncedBody), len(syncedBody))
	_, _, syncedTimedOut, syncedErr := request.RawRequest(target, syncedReq, cfg)
	if syncedErr != nil || syncedTimedOut {
		rep.Log("CL.TE: synced baseline timed out or errored for %s, skipping CL.TE scan", target.Host)
		dbg(cfg, "CL.TE: synced baseline failed (err=%v timeout=%v)", syncedErr, syncedTimedOut)
		return
	}
	dbg(cfg, "CL.TE: synced baseline OK")

	// Probe body: two chunks. The -6 truncation lands inside the second chunk
	// so the back-end (if it uses TE) waits for the missing bytes → TIMEOUT.
	// Body = "3\r\nx=y\r\n1\r\nZ\r\nQ\r\n\r\n" mirrors Java malformedClose=true body.
	const probeBody = "3\r\nx=y\r\n1\r\nZ\r\nQ\r\n\r\n"
	const truncateCL = 6 // Java contentLengthOffset = -6

	// Add Transfer-Encoding: chunked to the base BEFORE applying TE permutations.
	// ApplyTE techniques work by REPLACING or MODIFYING an existing TE header.
	// If the base has no TE header, replaceBytes() finds nothing → result == req →
	// ApplyTE returns nil → technique is silently skipped.
	// Adding TE first ensures all ~50 techniques actually apply their mutations.
	baseWithTE := request.AddTE(workingBase)
	baseWithTE = request.SetConnection(baseWithTE, "close")

	for _, tech := range filterTechniques(permute.H1Techniques(), cfg.TechniquesFilter) {
		if tech.H2Only {
			continue
		}

		// ApplyTE mutates the existing Transfer-Encoding: chunked header.
		mutated := permute.ApplyTE(baseWithTE, tech.Name)
		if mutated == nil {
			continue
		}
		// Do NOT call AddTE here — TE was already added to baseWithTE above
		// and has been mutated by ApplyTE. Adding it again would undo the mutation.

		syncedBreakReq := request.SetContentLength(request.SetBody(mutated, probeBody), len(probeBody))
		_, _, syncedBreakTimedOut, _ := request.RawRequest(target, syncedBreakReq, cfg)
		if syncedBreakTimedOut {
			rep.Log("CL.TE: technique %s causes timeout even with full CL, skipping (FP guard)", tech.Name)
			dbg(cfg, "CL.TE [%s] syncedBreak TIMEOUT — FP, skip", tech.Name)
			continue
		}
		dbg(cfg, "CL.TE [%s] syncedBreak OK", tech.Name)

		// Actual probe: CL = bodyLen - 6, so front-end (CL) only forwards a
		// partial chunk body; back-end (TE) waits for the rest → TIMEOUT.
		cl := len(probeBody) - truncateCL
		probeReq := request.SetContentLength(request.SetBody(mutated, probeBody), cl)

		rep.Log("CL.TE probe: technique=%s method=%s target=%s cl=%d bodyLen=%d", tech.Name, probeMethod, target.Host, cl, len(probeBody))

		resp, probeElapsed, timedOut, err := request.RawRequest(target, probeReq, cfg)
		if err != nil {
			rep.Log("CL.TE send error (%s): %v", tech.Name, err)
			continue
		}

		delayed := cfg.IsDelayed(probeElapsed)
		dbg(cfg, "CL.TE [%s] PROBE → timeout=%v delayed=%v suspicious=%v status=%d elapsed=%v",
			tech.Name, timedOut, delayed, request.IsSuspiciousResponse(resp), request.StatusCode(resp), probeElapsed)

		// Detection signals:
		//   1. Hard timeout: no response at all (server hung completely)
		//   2. Delayed response: response arrived but took >> baseline (--calibrate)
		//   3. Suspicious response: status 400/405 + "GPOST"/"Unrecognised"
		if timedOut || delayed || request.IsSuspiciousResponse(resp) {
			confirmed := request.ConfirmProbe(target, probeReq, cfg, rep.Log, "CL.TE")
			sev := report.SeverityProbable
			if confirmed {
				sev = report.SeverityConfirmed
			}
			desc := "Front-end uses Content-Length; back-end uses Transfer-Encoding."
			if probeMethod != configuredMethod {
				desc += fmt.Sprintf(" Probe sent as %s (upgraded from %s — CL.TE requires a body).", probeMethod, configuredMethod)
			}
			evidence := fmt.Sprintf("timeout=%v delayed=%v (elapsed=%v threshold=%v) suspicious=%v confirmed=%v",
				timedOut, delayed, probeElapsed, cfg.DelayThreshold, request.IsSuspiciousResponse(resp), confirmed)
			rep.Emit(report.Finding{
				Target:      target.String(),
				Method:      probeMethod,
				Severity:    sev,
				Type:        "CL.TE",
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
