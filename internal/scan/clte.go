package scan

// clte.go — CL.TE desync detection.
//
// Strategy (ChunkContentScan.java):
//   The front-end forwards N bytes (per Content-Length).
//   The back-end reads until it sees a chunked terminator.
//   We send CL=len(smuggledPrefix)+6 and body="0\r\n\r\nG" — the back-end stops
//   after the terminator (0\r\n\r\n) and leaves "G" in its read buffer,
//   which gets prepended to the next user's request → "GPOST".
//
// Detection: timeout or suspicious 400/405 from the back-end.
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

	for _, tech := range filterTechniques(permute.H1Techniques(), cfg.TechniquesFilter) {
		if tech.H2Only {
			continue
		}

		mutated := permute.ApplyTE(workingBase, tech.Name)
		if mutated == nil {
			continue
		}
		mutated = request.AddTE(mutated)
		mutated = request.SetConnection(mutated, "close")

		const smuggledPrefix = "G"
		chunkBody := fmt.Sprintf("0\r\n\r\n%s", smuggledPrefix)
		probeReq := request.SetContentLength(request.SetBody(mutated, chunkBody), len(chunkBody))

		rep.Log("CL.TE probe: technique=%s method=%s target=%s", tech.Name, probeMethod, target.Host)

		resp, _, timedOut, err := request.RawRequest(target, probeReq, cfg)
		if err != nil {
			rep.Log("CL.TE send error (%s): %v", tech.Name, err)
			continue
		}

		if timedOut || request.IsSuspiciousResponse(resp) {
			confirmed := request.ConfirmProbe(target, probeReq, cfg, rep.Log, "CL.TE")
			sev := report.SeverityProbable
			if confirmed {
				sev = report.SeverityConfirmed
			}
			rep.Emit(report.Finding{
				Target:      target.String(),
				Method:      probeMethod,
				Severity:    sev,
				Type:        "CL.TE",
				Technique:   tech.Name,
				Description: fmt.Sprintf("Front-end uses Content-Length; back-end uses Transfer-Encoding (method: %s)", probeMethod),
				Evidence:    fmt.Sprintf("timeout=%v status=%d confirmed=%v", timedOut, request.StatusCode(resp), confirmed),
				RawProbe:    request.Truncate(string(probeReq), 512),
				RawResponse: request.Truncate(string(resp), 512),
			})
			return // one finding per target per method is sufficient
		}
	}
}
