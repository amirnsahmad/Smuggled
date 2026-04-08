package request

// request.go — low-level HTTP request construction and wire helpers.
//
// All functions here operate on raw []byte request/response payloads to
// preserve exact wire formatting — no net/http normalisation is allowed.

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/permute"
	"github.com/smuggled/smuggled/internal/transport"
)

// ─── Constants ────────────────────────────────────────────────────────────────

// timeoutRatio: response time >= Timeout*timeoutRatio is considered a hang.
const TimeoutRatio = 0.8

// userAgent is the UA sent on all probes.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

// ─── Request builders ─────────────────────────────────────────────────────────

// BuildBaseRequest builds a minimal HTTP/1.1 request for the primary method in cfg.
func BuildBaseRequest(u *url.URL, cfg config.Config) []byte {
	return BuildRequestForMethod(u, config.EffectiveMethods(cfg)[0])
}

// buildRequestForMethod constructs a raw HTTP/1.1 request line for a specific method.
// Methods that do not carry a body (GET, HEAD, OPTIONS, TRACE) omit Content-* headers.
func BuildRequestForMethod(u *url.URL, method string) []byte {
	host := HostHeader(u)
	path := RequestPath(u)

	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: " + userAgent + "\r\n")
	if !config.IsBodylessMethod(method) {
		b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
		b.WriteString("Content-Length: 3\r\n")
	}
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	if !config.IsBodylessMethod(method) {
		b.WriteString("x=y")
	}
	return []byte(b.String())
}

// upgradeToBodyMethod returns a copy of base rewritten to POST if the configured
// method is bodyless and ForceMethod is not set. Logs the upgrade via rep.Log.
// Returns the (possibly modified) request and the effective method string.
func UpgradeToBodyMethod(base []byte, cfg config.Config, logFn func(string, ...any)) ([]byte, string) {
	configured := config.EffectiveMethods(cfg)[0]
	effective := config.EffectiveMethod(cfg, true)
	if effective != configured {
		logFn("upgrading method %s→%s for body-bearing probe (use --force-method to override)", configured, effective)
		base = permute.SetMethod(base, effective)
		base = permute.SetHeader(base, "Content-Type", "application/x-www-form-urlencoded")
		base = permute.SetHeader(base, "Content-Length", "3")
		base = SetBody(base, "x=y")
	}
	return base, effective
}

// ─── Payload mutation helpers ─────────────────────────────────────────────────

// setBody replaces everything after \r\n\r\n in req with body.
func SetBody(req []byte, body string) []byte {
	idx := bytes.Index(req, []byte("\r\n\r\n"))
	if idx < 0 {
		return append(req, []byte(body)...)
	}
	out := make([]byte, idx+4+len(body))
	copy(out, req[:idx+4])
	copy(out[idx+4:], body)
	return out
}

// setContentLength sets (or adds) the Content-Length header.
func SetContentLength(req []byte, n int) []byte {
	return permute.SetHeader(req, "Content-Length", fmt.Sprintf("%d", n))
}

// setConnection sets (or adds) the Connection header.
func SetConnection(req []byte, value string) []byte {
	return permute.SetHeader(req, "Connection", value)
}

// addTE adds Transfer-Encoding: chunked if not already present.
func AddTE(req []byte) []byte {
	if !bytes.Contains(bytes.ToLower(req), []byte("transfer-encoding:")) {
		return permute.SetHeader(req, "Transfer-Encoding", "chunked")
	}
	return req
}

// bypassCLFix lowercases "Content-Length" → "Content-length" to prevent some
// middleware from normalising a duplicate CL header before forwarding.
// Mirrors ChunkContentScan.bypassContentLengthFix() in the Java original.
func BypassCLFix(req []byte) []byte {
	cl := permute.GetHeader(req, "Content-Length")
	return permute.SetHeader(req, "content-length", cl)
}

// ─── Network helpers ──────────────────────────────────────────────────────────

// rawRequest opens a fresh connection, sends payload, and returns the response.
// Returns timedOut=true and resp=nil if the server hangs past cfg.Timeout.
func RawRequest(target *url.URL, payload []byte, cfg config.Config) (resp []byte, elapsed time.Duration, timedOut bool, err error) {
	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return nil, 0, false, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err = conn.Send(payload); err != nil {
		return nil, 0, false, fmt.Errorf("send: %w", err)
	}

	data, dur, readErr := conn.RecvWithTimeout(cfg.Timeout)
	if len(data) == 0 && readErr {
		return nil, dur, true, nil
	}
	return data, dur, false, nil
}

// connectivityCheck fires a plain GET to verify the target is reachable.
func ConnectivityCheck(u *url.URL, cfg config.Config) bool {
	req := []byte("GET " + RequestPath(u) + " HTTP/1.1\r\nHost: " + HostHeader(u) + "\r\nConnection: close\r\n\r\n")
	resp, _, timedOut, err := RawRequest(u, req, cfg)
	return err == nil && !timedOut && len(resp) > 0
}

// ─── Response parsing helpers ─────────────────────────────────────────────────

// statusCode extracts the 3-digit HTTP status code from raw response bytes.
func StatusCode(resp []byte) int {
	// HTTP/1.1 200 …  → bytes 9-11
	if len(resp) < 12 {
		return 0
	}
	code := 0
	fmt.Sscanf(string(resp[9:12]), "%d", &code)
	return code
}

// containsStr returns true if resp contains s (case-insensitive).
func ContainsStr(resp []byte, s string) bool {
	return bytes.Contains(bytes.ToLower(resp), []byte(strings.ToLower(s)))
}

// isSuspiciousResponse returns true when a response looks like a poisoned-pipeline
// reply (e.g. "GPOST" method or "Unrecognised method" from the back-end).
func IsSuspiciousResponse(resp []byte) bool {
	code := StatusCode(resp)
	if code != 400 && code != 405 {
		return false
	}
	return bytes.Contains(resp, []byte("Unrecognised")) ||
		bytes.Contains(resp, []byte("GPOST")) ||
		bytes.Contains(resp, []byte("Invalid method"))
}

// ─── Specialised request builders ────────────────────────────────────────────

// buildKeepAliveRequest builds a minimal POST with Connection: keep-alive and CL=0.
// Used by CL.0 and connection-state probes.
func BuildKeepAliveRequest(method, path, host string) []byte {
	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("User-Agent: " + userAgent + "\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	b.WriteString("\r\n")
	return []byte(b.String())
}

// buildGETRequest builds a minimal GET to a path from a gadget request-line string.
// requestLine is like "GET /robots.txt HTTP/1.1".
func BuildGETRequest(requestLine, host string) []byte {
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return nil
	}
	path := parts[1]
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	return []byte(b.String())
}

// ─── Probe confirmation ───────────────────────────────────────────────────────

// confirmProbe resends payload cfg.ConfirmReps+2 times and counts timeouts.
// Returns true when at least cfg.ConfirmReps attempts timed out.
// logFn is called with progress info (e.g. rep.Log).
func ConfirmProbe(target *url.URL, payload []byte, cfg config.Config, logFn func(string, ...any), label string) bool {
	hits := 0
	needed := cfg.ConfirmReps
	for i := 0; i < needed+2; i++ {
		_, _, timedOut, err := RawRequest(target, payload, cfg)
		if err == nil && timedOut {
			hits++
		}
	}
	logFn("%s confirmation: %d/%d timeouts", label, hits, needed)
	return hits >= needed
}

// ─── String utilities ────────────────────────────────────────────────────────

// truncate shortens s to max bytes, appending "…" if trimmed.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// ─── URL helpers ─────────────────────────────────────────────────────────────

func HostHeader(u *url.URL) string {
	h := u.Hostname()
	if p := u.Port(); p != "" {
		h = h + ":" + p
	}
	return h
}

func RequestPath(u *url.URL) string {
	if p := u.RequestURI(); p != "" {
		return p
	}
	return "/"
}
