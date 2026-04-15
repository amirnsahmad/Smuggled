package scan

// h2tunnel.go — HTTP/2 tunnel desync + H2.TE via HEAD/GET (HeadScanTE.java + H2TunnelScan.java)
//
// Two related attacks:
//
// 1. H2 Tunnel (H2TunnelScan.java):
//    Send an H2 request (GET/POST/HEAD/OPTIONS) whose body contains an
//    invalid HTTP/1.1 request. If the front-end tunnels H2→H1 without
//    stripping the body, the back-end processes the nested request.
//    Detection: look for a "mixed response" — an HTTP/1.x response
//    line inside the body of the H2 response (HeadScanTE.mixedResponse).
//
// 2. H2.TE Tunnel (HeadScanTE.java):
//    Send an H2 request with Transfer-Encoding: chunked and a smuggled
//    body (e.g. "FOO BAR AAH\r\n\r\n"). The front-end may not strip the
//    TE header before downgrading to H1, causing the back-end to read
//    the body as a chunked stream and expose the tunnelled content.
//    Detection: same mixedResponse check.

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/request"
)

// h1ResponseLine mirrors HeadScanTE.java: Pattern.compile("HTTP/1[.][01] [0-9]")
// Matches a proper HTTP/1.0 or HTTP/1.1 status line in a DATA frame body.
var h1ResponseLine = regexp.MustCompile(`HTTP/1\.[01] [0-9]`)

const h2trigger = "FOO BAR AAH\r\n\r\n"
const h2triggerShort = "FOO\r\n\r\n"

var h2TunnelMethods = []string{"GET", "POST", "HEAD", "OPTIONS"}

// ScanH2Tunnel probes for H2 tunnel desync (body passes through to back-end).
func ScanH2Tunnel(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("H2Tunnel")
	if target.Scheme != "https" {
		return
	}
	if !request.ProbeH2(target, cfg) {
		rep.Log("H2Tunnel: %s does not negotiate h2, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	for _, method := range h2TunnelMethods {
		for _, trigger := range []string{h2trigger, h2triggerShort} {
			rep.Log("H2Tunnel probe: method=%s trigger=%q target=%s", method, trigger, host)

			h2resp, err := h2RawRequest(target, method, path, host, trigger, nil, cfg)
			if err != nil {
				rep.Log("H2Tunnel error: %v", err)
				continue
			}

			if mixedH2Response(h2resp) {
				rep.Emit(report.Finding{
					Target:   target.String(),
					Method:      "HTTP/2",
					Severity: report.SeverityConfirmed,
					Type:     "H2-tunnel",
					Technique: fmt.Sprintf("H2-tunnel/%s", method),
					Description: fmt.Sprintf(
						"H2 tunnel desync: an HTTP/1.x response was detected inside the H2 response body "+
							"(method=%s). The front-end is tunnelling the request body to the back-end without "+
							"stripping it, allowing injection of arbitrary HTTP/1.1 requests.",
						method),
					Evidence: fmt.Sprintf("trigger=%q mixed_response=true", trigger),
				})
				if cfg.ExitOnFind {
					return
				}
			}
		}
	}
}

// ScanHeadScanTE probes for H2.TE tunnel via Transfer-Encoding injection in H2 (HeadScanTE.java).
func ScanHeadScanTE(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("HeadScanTE")
	if target.Scheme != "https" {
		return
	}
	if !request.ProbeH2(target, cfg) {
		rep.Log("HeadScanTE: %s does not negotiate h2, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	// TE permutations to inject — mirroring h2Permutations in DesyncBox.java
	tePermutations := []struct {
		name  string
		extra map[string]string // extra headers to inject
	}{
		{"vanilla", nil},
		{"http2hide", map[string]string{"Foo": "b\r\nTransfer-Encoding: chunked\r\nx"}},
		{"h2colon", map[string]string{"Transfer-Encoding`chunked ": "chunked"}},
		{"h2space", map[string]string{"Transfer-Encoding chunked ": "chunked"}},
		{"h2prefix", map[string]string{":transfer-encoding": "chunked"}},
	}

	for _, method := range []string{"GET", "POST"} {
		for _, perm := range tePermutations {
			// Build extra headers — override Transfer-Encoding with obfuscated version
			extraHeaders := map[string]string{
				"transfer-encoding": "chunked",
			}
			for k, v := range perm.extra {
				extraHeaders[k] = v
				delete(extraHeaders, "transfer-encoding") // remove vanilla TE if injecting obfuscated
			}

			// Also inject method-override headers
			for _, h := range methodOverrideHeaders {
				extraHeaders[strings.ToLower(h)] = "HEAD"
			}

			rep.Log("HeadScanTE probe: method=%s perm=%s target=%s", method, perm.name, host)

			// Send with trigger as body
			h2resp, err := h2RawRequest(target, method, path, host, h2trigger, extraHeaders, cfg)
			if err != nil {
				continue
			}

			if mixedH2Response(h2resp) {
				rep.Emit(report.Finding{
					Target:   target.String(),
					Method:      "HTTP/2",
					Severity: report.SeverityConfirmed,
					Type:     "H2.TE-tunnel",
					Technique: fmt.Sprintf("HeadTE/%s/%s", method, perm.name),
					Description: fmt.Sprintf(
						"H2.TE tunnel desync confirmed: mixed HTTP/1.x response detected in H2 response body "+
							"(method=%s, TE permutation=%s). The back-end is processing tunnelled requests.",
						method, perm.name),
					Evidence: "mixed_h2_response=true",
				})
				if cfg.ExitOnFind {
					return
				}
			}
		}
	}
}

// ScanH2TunnelCL probes for H2 tunnel desync via CL-confusing techniques.
// Maps to H2TunnelScan.java.
//
// Two complementary techniques are tested:
//
//  1. Via null-byte: embeds a null byte in the Via header to force some proxies
//     into opaque tunnel mode — they forward the body without inspection.
//
//  2. Fakecontentlength: strips the real content-length header and adds
//     "Fakecontentlength: 0". Some proxies normalize this fake header into
//     Content-Length: 0 on the downgraded H1 request, causing CL.0 desync:
//     the body (FOO BAR AAH\r\n\r\n) is left in the back-end TCP buffer as
//     the start of a new H1 request.
func ScanH2TunnelCL(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	cfg = cfg.WithDebugScope("H2TunnelCL")
	if target.Scheme != "https" {
		return
	}
	if !request.ProbeH2(target, cfg) {
		rep.Log("H2TunnelCL: %s does not negotiate h2, skipping", target.Host)
		return
	}

	path := target.RequestURI()
	if path == "" {
		path = "/"
	}
	host := target.Hostname()

	type clPerm struct {
		name  string
		extra map[string]string
	}

	perms := []clPerm{
		// Via null-byte: forces opaque tunnel mode in some proxies.
		{
			name:  "via-null",
			extra: map[string]string{"via": "x (comment\x00hmmm)"},
		},
		// Fakecontentlength: fake CL header with value 0, real CL suppressed.
		// Matches H2TunnelScan.java — some proxies treat this fake header name
		// as content-length, causing CL.0 on the downgraded H1 request.
		{
			name: "fakecontentlength",
			extra: map[string]string{
				"content-length":    "", // suppress real CL
				"fakecontentlength": "0",
			},
		},
	}

	for _, perm := range perms {
		for _, method := range h2TunnelMethods {
			for _, trigger := range []string{h2trigger, h2triggerShort} {
				rep.Log("H2TunnelCL probe: perm=%s method=%s trigger=%q target=%s",
					perm.name, method, trigger, host)

				h2resp, err := h2RawRequest(target, method, path, host, trigger, perm.extra, cfg)
				if err != nil {
					rep.Log("H2TunnelCL error: %v", err)
					continue
				}

				if mixedH2Response(h2resp) {
					rep.Emit(report.Finding{
						Target:   target.String(),
						Method:   "HTTP/2",
						Severity: report.SeverityConfirmed,
						Type:     "H2-tunnel-CL",
						Technique: fmt.Sprintf("H2-tunnel-CL/%s/%s", perm.name, method),
						Description: fmt.Sprintf(
							"H2 CL-based tunnel desync: an HTTP/1.x response was detected inside "+
								"the H2 response body (method=%s, technique=%s). The front-end "+
								"forwarded the request body to the back-end without stripping it.",
							method, perm.name),
						Evidence: fmt.Sprintf("trigger=%q perm=%s mixed_response=true", trigger, perm.name),
					})
					if cfg.ExitOnFind {
						return
					}
				}
			}
		}
	}
}

// ─── H2 single-connection probe ──────────────────────────────────────────────

// h2AttackAndProbe sends an attack request on stream 1 and a probe GET on stream 3
// over the same H2 connection.
//
// Using a single connection is critical for CL.0 detection: the H2 front-end
// multiplexes both streams onto the same back-end TCP connection. When the attack
// body is left in the back-end's TCP buffer (CL.0 effect), stream 3 arrives on
// that same connection and triggers the poisoned state — whereas two separate
// connections may hit different back-end workers and miss the poisoning window.
func h2AttackAndProbe(
	target *url.URL,
	method, path, host, body string,
	extraHeaders map[string]string,
	cfg config.Config,
) (attackResp, probeResp *h2Response, err error) {
	// Merge cfg.ExtraHeaders / cfg.Cookies without overriding probe-specific keys.
	if cfgExtra := request.ExtraH2Headers(cfg); len(cfgExtra) > 0 {
		merged := make(map[string]string, len(cfgExtra)+len(extraHeaders))
		for k, v := range cfgExtra {
			merged[k] = v
		}
		for k, v := range extraHeaders {
			merged[k] = v
		}
		extraHeaders = merged
	}

	addr := target.Hostname() + ":443"
	if p := target.Port(); p != "" {
		addr = target.Hostname() + ":" + p
	}

	tlsCfg := &tls.Config{
		ServerName:         target.Hostname(),
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec
		NextProtos:         []string{"h2"},
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("h2 dial: %w", err)
	}
	defer conn.Close()

	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, nil, fmt.Errorf("h2 not negotiated")
	}

	conn.SetDeadline(time.Now().Add(cfg.Timeout)) //nolint:errcheck

	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, nil, err
	}

	framer := http2.NewFramer(conn, conn)
	framer.AllowIllegalWrites = true
	framer.AllowIllegalReads = true

	if err := framer.WriteSettings(); err != nil {
		return nil, nil, err
	}

	// Resolve pseudo-header overrides for the attack stream.
	pseudoMethod := method
	pseudoPath := path
	pseudoScheme := "https"
	pseudoAuthority := host
	regularHeaders := make(map[string]string)
	for k, v := range extraHeaders {
		switch k {
		case ":method":
			pseudoMethod = v
		case ":path":
			pseudoPath = v
		case ":scheme":
			pseudoScheme = v
		case ":authority":
			pseudoAuthority = v
		default:
			regularHeaders[k] = v
		}
	}

	// Shared HPACK encoder — connection-scoped dynamic table, same for both streams.
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)

	// ── Stream 1: Attack ──────────────────────────────────────────────────
	clValue := fmt.Sprintf("%d", len(body))
	suppressCL := false
	if override, ok := regularHeaders["content-length"]; ok {
		if override == "" {
			suppressCL = true // sentinel: caller explicitly wants no CL header
		} else {
			clValue = override
		}
		delete(regularHeaders, "content-length")
	}
	if cfg.Debug >= 2 {
		dumpCL := clValue
		if suppressCL {
			dumpCL = "(suppressed)"
		}
		dbg(cfg, "%s", h2DumpRequest(1, pseudoMethod, pseudoPath, pseudoScheme, pseudoAuthority, dumpCL, regularHeaders, body))
	}
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: pseudoMethod})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: pseudoPath})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: pseudoScheme})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: pseudoAuthority})
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/x-www-form-urlencoded"})
	if !suppressCL {
		enc.WriteField(hpack.HeaderField{Name: "content-length", Value: clValue})
	}
	enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: request.UserAgent})
	enc.WriteField(hpack.HeaderField{Name: "accept-encoding", Value: "identity"})
	for k, v := range regularHeaders {
		enc.WriteField(hpack.HeaderField{Name: k, Value: v})
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return nil, nil, err
	}
	if err := framer.WriteData(1, true, []byte(body)); err != nil {
		return nil, nil, err
	}

	// ── Stream 3: Probe (plain GET, no body) ─────────────────────────────
	// H2 client-initiated streams use odd numbers: 1, 3, 5, …
	hbuf.Reset()
	if cfg.Debug >= 2 {
		dbg(cfg, "%s", h2DumpRequest(3, "GET", path, "https", host, "(not sent)", nil, ""))
	}
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: path})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: host})
	enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: request.UserAgent})
	enc.WriteField(hpack.HeaderField{Name: "accept-encoding", Value: "identity"})
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      3,
		BlockFragment: hbuf.Bytes(),
		EndStream:     true,
		EndHeaders:    true,
	}); err != nil {
		return nil, nil, err
	}

	// ── Read frames, routing by stream ID ────────────────────────────────
	attackResp = &h2Response{}
	probeResp = &h2Response{}
	hpackDec := hpack.NewDecoder(4096, nil)

	var attackBuf, probeBuf bytes.Buffer
	attackDone, probeDone := false, false
	deadline := time.Now().Add(cfg.Timeout)

	for (!attackDone || !probeDone) && time.Now().Before(deadline) {
		frame, err := framer.ReadFrame()
		if err != nil {
			dbg(cfg, "h2AttackAndProbe: read frame error: %v", err)
			break
		}
		switch f := frame.(type) {
		case *http2.DataFrame:
			if f.StreamID == 1 {
				attackBuf.Write(f.Data())
				if f.StreamEnded() {
					attackDone = true
				}
			} else if f.StreamID == 3 {
				probeBuf.Write(f.Data())
				if f.StreamEnded() {
					probeDone = true
				}
			}
			dbg(cfg, "h2AttackAndProbe: [DATA stream=%d len=%d end=%v]",
				f.StreamID, len(f.Data()), f.StreamEnded())
		case *http2.HeadersFrame:
			dest := attackResp
			if f.StreamID == 3 {
				dest = probeResp
			}
			if fields, decErr := hpackDec.DecodeFull(f.HeaderBlockFragment()); decErr == nil {
				for _, hf := range fields {
					dest.Headers = append(dest.Headers, hf)
					if hf.Name == ":status" {
						fmt.Sscanf(hf.Value, "%d", &dest.Status)
					}
					dbg(cfg, "h2AttackAndProbe: [HEADER stream=%d] %s: %s",
						f.StreamID, hf.Name, hf.Value)
				}
			}
			if f.StreamEnded() {
				if f.StreamID == 1 {
					attackDone = true
				} else if f.StreamID == 3 {
					probeDone = true
				}
			}
		case *http2.RSTStreamFrame:
			dbg(cfg, "h2AttackAndProbe: [RST stream=%d code=%v]", f.StreamID, f.ErrCode)
			if f.StreamID == 1 {
				attackDone = true
			} else if f.StreamID == 3 {
				probeDone = true
			}
		case *http2.GoAwayFrame:
			dbg(cfg, "h2AttackAndProbe: [GOAWAY code=%v]", f.ErrCode)
			attackDone = true
			probeDone = true
		case *http2.SettingsFrame:
			if !f.IsAck() {
				framer.WriteSettingsAck() //nolint:errcheck
			}
		}
	}

	attackResp.Body = attackBuf.Bytes()
	probeResp.Body = probeBuf.Bytes()
	if cfg.Debug >= 2 {
		dbg(cfg, "%s", h2DumpResponse(1, attackResp))
		dbg(cfg, "%s", h2DumpResponse(3, probeResp))
	}
	return attackResp, probeResp, nil
}

// ─── H2 raw framing ──────────────────────────────────────────────────────────

// h2Response holds the structured result of an H2 request, separating decoded
// header fields from raw DATA frame body bytes.
type h2Response struct {
	Status  int    // :status pseudo-header value (e.g. 200, 404), 0 if absent
	Headers []hpack.HeaderField
	Body    []byte // concatenated DATA frame payloads
}

// h2RawRequest sends a raw HTTP/2 request using our own HPACK-encoded HEADERS frame.
// body is appended as a DATA frame; extraHeaders are injected after pseudo-headers.
//
// If extraHeaders contains a pseudo-header key (e.g. ":method", ":path", ":scheme"),
// the default value is overridden instead of duplicated — this avoids PROTOCOL_ERROR
// from servers that reject duplicate pseudo-headers (RFC 7540 §8.1.2.1).
func h2RawRequest(target *url.URL, method, path, host, body string, extraHeaders map[string]string, cfg config.Config) (*h2Response, error) {
	// Merge cfg.ExtraHeaders and cfg.Cookies into extraHeaders without
	// overriding probe-specific keys already set by the caller.
	if cfgExtra := request.ExtraH2Headers(cfg); len(cfgExtra) > 0 {
		merged := make(map[string]string, len(cfgExtra)+len(extraHeaders))
		for k, v := range cfgExtra {
			merged[k] = v
		}
		// Caller's keys take precedence
		for k, v := range extraHeaders {
			merged[k] = v
		}
		extraHeaders = merged
	}
	addr := target.Hostname() + ":443"
	if p := target.Port(); p != "" {
		addr = target.Hostname() + ":" + p
	}

	tlsCfg := &tls.Config{
		ServerName:         target.Hostname(),
		InsecureSkipVerify: cfg.SkipTLSVerify, //nolint:gosec
		NextProtos:         []string{"h2"},
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("h2 dial: %w", err)
	}
	defer conn.Close()

	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return nil, fmt.Errorf("h2 not negotiated")
	}

	conn.SetDeadline(time.Now().Add(cfg.Timeout)) //nolint:errcheck

	// Client preface
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return nil, err
	}

	framer := http2.NewFramer(conn, conn)
	framer.AllowIllegalWrites = true
	framer.AllowIllegalReads = true

	if err := framer.WriteSettings(); err != nil {
		return nil, err
	}

	// Build pseudo-headers with overrides from extraHeaders
	pseudoMethod := method
	pseudoPath := path
	pseudoScheme := "https"
	pseudoAuthority := host
	regularHeaders := make(map[string]string)

	for k, v := range extraHeaders {
		switch k {
		case ":method":
			pseudoMethod = v
		case ":path":
			pseudoPath = v
		case ":scheme":
			pseudoScheme = v
		case ":authority":
			pseudoAuthority = v
		default:
			regularHeaders[k] = v
		}
	}

	// HEADERS frame
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	enc.WriteField(hpack.HeaderField{Name: ":method", Value: pseudoMethod})
	enc.WriteField(hpack.HeaderField{Name: ":path", Value: pseudoPath})
	enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: pseudoScheme})
	enc.WriteField(hpack.HeaderField{Name: ":authority", Value: pseudoAuthority})
	// content-type and content-length are only emitted when there is a body.
	// In HTTP/2 the DATA frame length already communicates body size to the peer
	// (RFC 9113 §8.1.2.6 permits omitting content-length). Sending CL=0 on a
	// bodyless GET is redundant and may fingerprint the scanner.
	// An explicit override via extraHeaders (including "" to suppress) always wins.
	clValue := fmt.Sprintf("%d", len(body))
	suppressCL := body == "" // no body → no CL by default
	if override, ok := regularHeaders["content-length"]; ok {
		if override == "" {
			suppressCL = true
		} else {
			suppressCL = false
			clValue = override
		}
		delete(regularHeaders, "content-length")
	}
	enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/x-www-form-urlencoded"})
	if !suppressCL {
		enc.WriteField(hpack.HeaderField{Name: "content-length", Value: clValue})
	}
	enc.WriteField(hpack.HeaderField{Name: "user-agent", Value: request.UserAgent})
	enc.WriteField(hpack.HeaderField{Name: "accept-encoding", Value: "identity"})
	for k, v := range regularHeaders {
		enc.WriteField(hpack.HeaderField{Name: k, Value: v, Sensitive: false})
	}

	if cfg.Debug >= 2 {
		dbg(cfg, "%s", h2DumpRequest(1, pseudoMethod, pseudoPath, pseudoScheme, pseudoAuthority, clValue, regularHeaders, body))
	}

	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		return nil, err
	}

	// DATA frame
	if err := framer.WriteData(1, true, []byte(body)); err != nil {
		return nil, err
	}

	// Read response frames — decode HEADERS via HPACK, collect DATA separately.
	resp := &h2Response{}
	hpackDec := hpack.NewDecoder(4096, nil)
	var dataBuf bytes.Buffer
	// Note: conn.SetDeadline above already bounds the total time. Per-frame
	// deadlines would mask H2.TE timeout signals (back-end hanging on inflated
	// chunk) as "empty response" — rely on the connection deadline instead.
	startRead := time.Now()
	deadline := time.Now().Add(cfg.Timeout)
	for time.Now().Before(deadline) {
		frame, err := framer.ReadFrame()
		if err != nil {
			dbg(cfg, "  h2Raw: read frame error after %v: %v", time.Since(startRead), err)
			break
		}
		switch f := frame.(type) {
		case *http2.DataFrame:
			dataBuf.Write(f.Data())
			dbg(cfg, "  h2Raw: [DATA stream=%d len=%d end=%v]", f.StreamID, len(f.Data()), f.StreamEnded())
			if f.StreamEnded() {
				goto done
			}
		case *http2.HeadersFrame:
			if fields, err := hpackDec.DecodeFull(f.HeaderBlockFragment()); err == nil {
				for _, hf := range fields {
					resp.Headers = append(resp.Headers, hf)
					if hf.Name == ":status" {
						fmt.Sscanf(hf.Value, "%d", &resp.Status)
					}
					dbg(cfg, "  h2Raw: [HEADER] %s: %s", hf.Name, hf.Value)
				}
			}
			dbg(cfg, "  h2Raw: [HEADERS stream=%d status=%d end=%v]", f.StreamID, resp.Status, f.StreamEnded())
			if f.StreamEnded() {
				goto done
			}
		case *http2.RSTStreamFrame:
			dbg(cfg, "  h2Raw: [RST_STREAM code=%v]", f.ErrCode)
			goto done
		case *http2.GoAwayFrame:
			dbg(cfg, "  h2Raw: [GOAWAY code=%v]", f.ErrCode)
			goto done
		case *http2.SettingsFrame:
			if !f.IsAck() {
				framer.WriteSettingsAck() //nolint:errcheck
				dbg(cfg, "  h2Raw: [SETTINGS ACK sent]")
			}
		default:
			dbg(cfg, "  h2Raw: [%T]", frame)
		}
	}
done:
	resp.Body = dataBuf.Bytes()
	if cfg.Debug >= 2 {
		dbg(cfg, "%s", h2DumpResponse(1, resp))
	}
	return resp, nil
}

// h2DumpRequest formats a human-readable H2 request dump for --debug 2.
func h2DumpRequest(streamID int, pseudoMethod, pseudoPath, pseudoScheme, pseudoAuthority, clValue string, regularHeaders map[string]string, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--- H2 REQUEST DUMP (stream %d) ---\n", streamID)
	fmt.Fprintf(&b, ":method: %s\n", pseudoMethod)
	fmt.Fprintf(&b, ":path: %s\n", pseudoPath)
	fmt.Fprintf(&b, ":scheme: %s\n", pseudoScheme)
	fmt.Fprintf(&b, ":authority: %s\n", pseudoAuthority)
	fmt.Fprintf(&b, "content-length: %s\n", clValue)
	for k, v := range regularHeaders {
		fmt.Fprintf(&b, "%s: %s\n", k, v)
	}
	if body != "" {
		fmt.Fprintf(&b, "[DATA] %s\n", request.Truncate(body, 512))
	}
	b.WriteString("--- END H2 REQUEST ---")
	return b.String()
}

// h2DumpResponse formats a human-readable H2 response dump for --debug 2.
func h2DumpResponse(streamID int, resp *h2Response) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--- H2 RESPONSE DUMP (stream %d) ---\n", streamID)
	for _, hf := range resp.Headers {
		fmt.Fprintf(&b, "%s: %s\n", hf.Name, hf.Value)
	}
	if len(resp.Body) > 0 {
		fmt.Fprintf(&b, "[BODY] %s\n", request.Truncate(string(resp.Body), 512))
	} else {
		b.WriteString("[BODY] (empty)\n")
	}
	b.WriteString("--- END H2 RESPONSE ---")
	return b.String()
}

// mixedH2Response detects an HTTP/1.x response line inside an H2 response body.
// This is the Go equivalent of HeadScanTE.mixedResponse() in Java.
//
// Only inspects the DATA frame body (resp.Body), not the HPACK-encoded HEADERS,
// to avoid false positives from binary HPACK bytes that might coincidentally
// match the regex.
func mixedH2Response(resp *h2Response) bool {
	if resp == nil {
		return false
	}
	return h1ResponseLine.Match(resp.Body)
}

