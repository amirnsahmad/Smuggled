package request

// request.go — low-level HTTP request construction and wire helpers.
//
// All functions here operate on raw []byte request/response payloads to
// preserve exact wire formatting — no net/http normalisation is allowed.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/permute"
	"github.com/smuggled/smuggled/internal/transport"
)

// ─── Constants ────────────────────────────────────────────────────────────────

// timeoutRatio: response time >= Timeout*timeoutRatio is considered a hang.
const TimeoutRatio = 0.8

// UserAgent is the UA sent on all probes.
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

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
	b.WriteString("User-Agent: " + UserAgent + "\r\n")
	b.WriteString("Accept-Encoding: identity\r\n")
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

// InjectExtraHeaders injects cfg.ExtraHeaders and cfg.Cookies into a raw H1
// request, inserting them before the final \r\n\r\n.
// Existing headers are not duplicated — if a header name from ExtraHeaders
// already exists in req, it is replaced.
func InjectExtraHeaders(req []byte, cfg config.Config) []byte {
	if len(cfg.ExtraHeaders) == 0 && cfg.Cookies == "" {
		return req
	}

	for _, h := range cfg.ExtraHeaders {
		colon := strings.IndexByte(h, ':')
		if colon <= 0 {
			continue
		}
		name := strings.TrimSpace(h[:colon])
		value := strings.TrimSpace(h[colon+1:])
		req = permute.SetHeader(req, name, value)
	}

	if cfg.Cookies != "" {
		// Merge with existing Cookie header if present
		existing := permute.GetHeader(req, "Cookie")
		if existing != "" {
			req = permute.SetHeader(req, "Cookie", existing+"; "+cfg.Cookies)
		} else {
			req = permute.SetHeader(req, "Cookie", cfg.Cookies)
		}
	}

	return req
}

// ExtraH2Headers returns a map of additional H2 headers from cfg.ExtraHeaders
// and cfg.Cookies, suitable for merging into h2RawRequest's extraHeaders map.
func ExtraH2Headers(cfg config.Config) map[string]string {
	if len(cfg.ExtraHeaders) == 0 && cfg.Cookies == "" {
		return nil
	}
	out := make(map[string]string)
	for _, h := range cfg.ExtraHeaders {
		colon := strings.IndexByte(h, ':')
		if colon <= 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(h[:colon]))
		value := strings.TrimSpace(h[colon+1:])
		out[name] = value
	}
	if cfg.Cookies != "" {
		if existing, ok := out["cookie"]; ok {
			out["cookie"] = existing + "; " + cfg.Cookies
		} else {
			out["cookie"] = cfg.Cookies
		}
	}
	return out
}

// ParseSetCookies extracts all Set-Cookie values from a raw H1 response and
// returns them as a single "k=v; k2=v2" string ready to use as a Cookie header.
func ParseSetCookies(resp []byte) string {
	if len(resp) == 0 {
		return ""
	}
	// Find end of headers
	sep := bytes.Index(resp, []byte("\r\n\r\n"))
	if sep < 0 {
		sep = len(resp)
	}
	headers := resp[:sep]

	var cookies []string
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		lower := bytes.ToLower(line)
		if !bytes.HasPrefix(lower, []byte("set-cookie:")) {
			continue
		}
		value := bytes.TrimSpace(line[len("set-cookie:"):])
		// Only keep name=value part (before first semicolon)
		if idx := bytes.IndexByte(value, ';'); idx >= 0 {
			value = bytes.TrimSpace(value[:idx])
		}
		if len(value) > 0 {
			cookies = append(cookies, string(value))
		}
	}
	return strings.Join(cookies, "; ")
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
	payload = InjectExtraHeaders(payload, cfg)

	dl := cfg.DebugLog
	if dl != nil {
		firstLine := payload
		if i := bytes.IndexByte(payload, '\r'); i > 0 {
			firstLine = payload[:i]
		}
		dl("RawRequest → %s %q (%d bytes)", target.Host, string(firstLine), len(payload))
		if cfg.Debug >= 2 {
			dl("--- REQUEST DUMP ---\n%s\n--- END REQUEST ---", Truncate(string(payload), 4096))
		}
	}

	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		if dl != nil {
			dl("RawRequest dial error: %v", err)
		}
		return nil, 0, false, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err = conn.Send(payload); err != nil {
		if dl != nil {
			dl("RawRequest send error: %v", err)
		}
		return nil, 0, false, fmt.Errorf("send: %w", err)
	}

	data, dur, readErr := conn.RecvWithTimeout(cfg.Timeout)
	if len(data) == 0 && readErr {
		if dl != nil {
			dl("RawRequest ← TIMEOUT after %v (no data)", dur)
		}
		return nil, dur, true, nil
	}
	if dl != nil {
		status := StatusCode(data)
		dl("RawRequest ← status=%d len=%d elapsed=%v", status, len(data), dur)
		if cfg.Debug >= 2 {
			dl("--- RESPONSE DUMP ---\n%s\n--- END RESPONSE ---", Truncate(string(data), 4096))
		}
	}
	return data, dur, false, nil
}

// SendNoRecv sends a payload and immediately closes without reading the response.
// Used by CL.0 skip-read mode: the smuggle request is fired and we move on
// to the probe without waiting for the smuggle response.
func SendNoRecv(target *url.URL, payload []byte, cfg config.Config) error {
	dl := cfg.DebugLog
	conn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if err = conn.Send(payload); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	if dl != nil {
		dl("SendNoRecv → %s (%d bytes, skip read)", target.Host, len(payload))
		if cfg.Debug >= 2 {
			dl("--- REQUEST DUMP (no-recv) ---\n%s\n--- END REQUEST ---", Truncate(string(payload), 4096))
		}
	}
	return nil
}

// LastByteSyncProbe implements last-byte synchronization for CL.0 detection.
//
// It opens two connections simultaneously:
//  1. Probe connection: sends all but the last byte of probePayload
//  2. Smuggle connection: sends the full smuggle payload (no read)
//  3. Probe connection: sends the final byte, then reads the response
//
// This minimizes the gap between the smuggle landing on the backend and
// the probe arriving, maximizing the chance of catching a poisoned connection.
func LastByteSyncProbe(target *url.URL, smuggle, probe []byte, cfg config.Config) (resp []byte, elapsed time.Duration, timedOut bool, err error) {
	dl := cfg.DebugLog

	// Step 1: open probe connection, send all but last byte
	probeConn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return nil, 0, false, fmt.Errorf("probe dial: %w", err)
	}
	defer probeConn.Close()

	lastByte, err := probeConn.SendPartial(probe)
	if err != nil {
		return nil, 0, false, fmt.Errorf("probe partial send: %w", err)
	}
	if dl != nil {
		dl("LastByteSync: probe partial sent (%d bytes held back 1)", len(probe)-1)
		if cfg.Debug >= 2 {
			dl("--- REQUEST DUMP (probe) ---\n%s\n--- END REQUEST ---", Truncate(string(probe), 4096))
		}
	}

	// Step 2: open smuggle connection, send full payload, close immediately
	smuggleConn, err := transport.Dial(target, cfg.Timeout, cfg.Proxy, cfg.SkipTLSVerify)
	if err != nil {
		return nil, 0, false, fmt.Errorf("smuggle dial: %w", err)
	}
	if err = smuggleConn.Send(smuggle); err != nil {
		smuggleConn.Close()
		return nil, 0, false, fmt.Errorf("smuggle send: %w", err)
	}
	smuggleConn.Close()
	if dl != nil {
		dl("LastByteSync: smuggle sent (%d bytes)", len(smuggle))
		if cfg.Debug >= 2 {
			dl("--- REQUEST DUMP (smuggle) ---\n%s\n--- END REQUEST ---", Truncate(string(smuggle), 4096))
		}
	}

	// Step 3: fire the last byte of probe, then read response
	if err = probeConn.SendByte(lastByte); err != nil {
		return nil, 0, false, fmt.Errorf("probe last byte: %w", err)
	}

	data, dur, readErr := probeConn.RecvWithTimeout(cfg.Timeout)
	if len(data) == 0 && readErr {
		if dl != nil {
			dl("LastByteSync ← TIMEOUT after %v", dur)
		}
		return nil, dur, true, nil
	}
	if dl != nil {
		dl("LastByteSync ← status=%d len=%d elapsed=%v", StatusCode(data), len(data), dur)
		if cfg.Debug >= 2 {
			dl("--- RESPONSE DUMP (probe) ---\n%s\n--- END RESPONSE ---", Truncate(string(data), 4096))
		}
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
	b.WriteString("User-Agent: " + UserAgent + "\r\n")
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

// Truncate shortens s to max bytes, appending "…" if trimmed.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// SanitizeResponse decodes gzip/deflate if present and replaces non-printable
// bytes in the body with "." so the output is always readable plain text.
// The HTTP status line and headers are preserved verbatim; only the body is
// sanitized.
func SanitizeResponse(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}

	// Split at \r\n\r\n — headers vs body
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		// No separator — treat entire thing as headers (e.g. partial response)
		return sanitizeBytes(raw)
	}

	headers := raw[:idx+len(sep)]
	body := raw[idx+len(sep):]

	headerStr := strings.ToLower(string(headers))

	// Try to decode compressed body
	if strings.Contains(headerStr, "content-encoding: gzip") {
		if dec, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if decoded, err := io.ReadAll(dec); err == nil {
				body = decoded
			}
		}
	} else if strings.Contains(headerStr, "content-encoding: deflate") {
		if decoded, err := io.ReadAll(flate.NewReader(bytes.NewReader(body))); err == nil {
			body = decoded
		}
	}

	return sanitizeBytes(headers) + sanitizeBytes(body)
}

// sanitizeBytes replaces bytes that are not valid UTF-8 printable text with ".".
// ASCII control characters (except \t, \n, \r) are also replaced.
func sanitizeBytes(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			sb.WriteByte('.')
			b = b[1:]
			continue
		}
		// Allow tab, CR, LF; replace other control chars
		if r < 0x20 && r != '\t' && r != '\r' && r != '\n' {
			sb.WriteByte('.')
		} else {
			sb.WriteRune(r)
		}
		b = b[size:]
	}
	return sb.String()
}

// ─── Protocol probes ─────────────────────────────────────────────────────────

// ProbeH1 returns true if the target responds to a plain HTTP/1.1 request.
func ProbeH1(target *url.URL, cfg config.Config) bool {
	return ConnectivityCheck(target, cfg)
}

// ProbeH2 returns true if the target negotiates HTTP/2 via ALPN.
// For non-HTTPS targets it always returns false.
func ProbeH2(target *url.URL, cfg config.Config) bool {
	if target.Scheme != "https" {
		return false
	}
	addr := target.Hostname() + ":443"
	if p := target.Port(); p != "" {
		addr = target.Hostname() + ":" + p
	}
	tlsCfg := &tls.Config{
		ServerName:         target.Hostname(),
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec
		NextProtos:         []string{"h2", "http/1.1"},
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return false
	}
	defer conn.Close()
	return strings.Contains(conn.ConnectionState().NegotiatedProtocol, "h2")
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
