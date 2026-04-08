package scan

// clte.go — CL.TE desync detection
//
// Strategy (mirroring ChunkContentScan.java):
// 1. Send a request where CL says N bytes but body has a chunked terminator smuggled.
//    Front-end reads CL bytes and forwards. Back-end reads chunked, stops early,
//    leaving remainder poisoning the next request's start.
// 2. Confirm by timing: a second request to the same pipeline connection gets a timeout
//    because the back-end is waiting to finish reading the poisoned prefix.

import (
	"bytes"
	"fmt"
	"net/url"
	"time"

	"github.com/smuggled/smuggled/pkg/permute"
	"github.com/smuggled/smuggled/pkg/report"
)

// ScanCLTE runs CL.TE detection across all applicable permutations.
func ScanCLTE(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	// CL.TE requires a body-bearing method. If user chose a bodyless method
	// (GET/HEAD/OPTIONS) without --force-method, silently use POST for this probe.
	probeMethod := effectiveMethod(cfg, true)
	workingBase := base
	if probeMethod != effectiveMethods(cfg)[0] && len(cfg.Methods) > 0 {
		rep.Log("CL.TE: upgrading method %s→POST (body required; use --force-method to override)", effectiveMethods(cfg)[0])
		workingBase = permute.SetMethod(base, probeMethod)
		// Restore Content-Type and CL that may be missing on a GET base
		workingBase = permute.SetHeader(workingBase, "Content-Type", "application/x-www-form-urlencoded")
		workingBase = permute.SetHeader(workingBase, "Content-Length", "3")
		workingBase = setBody(workingBase, "x=y")
	}

	techniques := filterTechniques(permute.H1Techniques(), cfg.TechniquesFilter)

	for _, tech := range techniques {
		if tech.H2Only {
			continue
		}

		rep.Log("CL.TE probe: technique=%s target=%s method=%s", tech.Name, target.Host, probeMethod)

		mutated := permute.ApplyTE(workingBase, tech.Name)
		if mutated == nil {
			continue
		}
		mutated = addTE(mutated)
		mutated = setConnection(mutated, "close")

		smuggledPrefix := "G"
		chunkBody := fmt.Sprintf("0\r\n\r\n%s", smuggledPrefix)
		probeReq := setBody(mutated, chunkBody)
		probeReq = setContentLength(probeReq, len(chunkBody))

		resp, elapsed, timedOut, err := rawRequest(target, probeReq, cfg)
		if err != nil {
			rep.Log("CL.TE send error (%s): %v", tech.Name, err)
			continue
		}
		_ = elapsed

		if timedOut || (len(resp) > 0 && isSuspiciousResponse(resp)) {
			confirmed := confirmCLTE(target, mutated, smuggledPrefix, cfg, rep)
			sev := report.SeverityProbable
			if confirmed {
				sev = report.SeverityConfirmed
			}
			rep.Emit(report.Finding{
				Target:      target.String(),
				Severity:    sev,
				Type:        "CL.TE",
				Technique:   tech.Name,
				Description: fmt.Sprintf("Front-end uses Content-Length; back-end uses Transfer-Encoding (probe method: %s)", probeMethod),
				Evidence:    fmt.Sprintf("timeout=%v status=%d confirmed=%v", timedOut, statusCode(resp), confirmed),
				RawProbe:    truncate(string(probeReq), 512),
				RawResponse: truncate(string(resp), 512),
			})
			return
		}
	}
}

// confirmCLTE sends the desync payload multiple times to reduce false positives.
func confirmCLTE(target *url.URL, base []byte, prefix string, cfg Config, rep *report.Reporter) bool {
	confirmed := 0
	needed := cfg.ConfirmReps

	chunkBody := fmt.Sprintf("0\r\n\r\n%s", prefix)
	probeReq := setBody(base, chunkBody)
	probeReq = setContentLength(probeReq, len(chunkBody))

	for i := 0; i < needed+2; i++ {
		_, _, timedOut, err := rawRequest(target, probeReq, cfg)
		if err != nil {
			continue
		}
		if timedOut {
			confirmed++
		}
	}
	rep.Log("CL.TE confirmation: %d/%d timeouts", confirmed, needed)
	return confirmed >= needed
}

// isSuspiciousResponse checks whether a response looks like a poisoned pipeline reply
// (e.g. 400 Bad Request or method-not-allowed hinting at a smuggled prefix).
func isSuspiciousResponse(resp []byte) bool {
	code := statusCode(resp)
	if code == 400 || code == 405 {
		// Possible GPOST or similar back-end error
		if bytes.Contains(resp, []byte("Unrecognised")) ||
			bytes.Contains(resp, []byte("GPOST")) ||
			bytes.Contains(resp, []byte("Invalid method")) {
			return true
		}
	}
	return false
}

// timeoutRatio is the fraction of baseline normal response time that counts as a timeout.
const timeoutRatio = 0.8

// baselineResponseTime sends a normal request and returns median response time.
func baselineResponseTime(target *url.URL, base []byte, cfg Config) time.Duration {
	var total time.Duration
	n := 3
	for i := 0; i < n; i++ {
		_, elapsed, _, err := rawRequest(target, base, cfg)
		if err != nil {
			continue
		}
		total += elapsed
	}
	if n == 0 {
		return cfg.Timeout
	}
	return total / time.Duration(n)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
