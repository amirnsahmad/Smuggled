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

// ScanImplicitZero probes for implicit zero-CL GET desync.
func ScanImplicitZero(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	rep.Log("ImplicitZero probe: %s", target.Host)

	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	// Technique 1: GET with Transfer-Encoding: chunked + a smuggled body
	// RFC says GET has no body, but some parsers accept it.
	smuggledMethod := "GPOST"
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

	// Follow-up request to detect if the prefix was consumed
	followup := []byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")

	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		rep.Log("ImplicitZero: dial error: %v", err)
		return
	}
	defer conn.Close()

	if err := conn.Send(probeBytes); err != nil {
		return
	}
	r1, _, t1 := conn.RecvWithTimeout(cfg.Timeout)
	if t1 || len(r1) == 0 {
		rep.Log("ImplicitZero: no response to GET+chunked probe")
		return
	}

	// Check connection still alive
	if request.ContainsStr(r1, "connection: close") {
		return
	}

	// Send follow-up on same connection
	if err := conn.Send(followup); err != nil {
		return
	}
	r2, _, t2 := conn.RecvWithTimeout(cfg.Timeout)

	if !t2 && len(r2) > 0 {
		st2 := request.StatusCode(r2)
		if st2 == 400 || st2 == 405 || bytes.Contains(r2, []byte(smuggledMethod)) {
			rep.Emit(report.Finding{
				Target:      target.String(),
				Severity:    report.SeverityProbable,
				Type:        "implicit-zero-CL",
				Technique:   "GET-chunked-smuggle",
				Description: fmt.Sprintf("Follow-up request got status %d with smuggled method in response — implicit CL=0 GET desync", st2),
				Evidence:    fmt.Sprintf("r1_status=%d r2_status=%d", request.StatusCode(r1), st2),
				RawProbe:    request.Truncate(getChunked.String(), 512),
			})
			return
		}
	}

	// Technique 2: HEAD with body (some proxies strip HEAD body, back-end gets it)
	scanHeadDesync(target, host, path, cfg, rep)
}

func scanHeadDesync(target *url.URL, host, path string, cfg config.Config, rep *report.Reporter) {
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
	if t1 || len(r1) == 0 {
		return
	}
	if request.ContainsStr(r1, "connection: close") {
		return
	}

	conn.Send(followup) //nolint:errcheck
	r2, _, _ := conn.RecvWithTimeout(cfg.Timeout)

	if len(r2) > 0 && bytes.Contains(r2, []byte("GPOST")) {
		rep.Emit(report.Finding{
			Target:      target.String(),
			Severity:    report.SeverityProbable,
			Type:        "implicit-zero-CL",
			Technique:   "HEAD-body-smuggle",
			Description: "HEAD request with body smuggled prefix — follow-up reflected smuggled method",
			Evidence:    fmt.Sprintf("r2_status=%d", request.StatusCode(r2)),
			RawProbe:    request.Truncate(headReq.String(), 512),
		})
	}
}
