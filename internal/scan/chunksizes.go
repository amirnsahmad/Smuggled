package scan

// chunksizes.go — Chunk size / terminator parsing discrepancy probes
//
// Maps to ChunkSizeScan.java (James Kettle / PortSwigger 2025).
// Reference: https://w4ke.info/2025/06/18/funky-chunks.html
//
// Techniques detect disagreements between front-end and back-end on how
// alternative line terminators or chunk-extension fields are counted
// when determining the boundary of a chunk body.
//
// Eight variants:
//   TERM.EXT   — alternate terminator in chunk extension; sizes disagree
//   EXT.TERM   — chunk extension followed by alternate terminator
//   TERM.SPILL — alternate terminator inside chunk body causes size spill
//   SPILL.TERM — oversized chunk with alternate terminator inside body
//   ONE.TWO    — body with alternate terminator; FE counts 1 byte, BE counts 2
//   TWO.ONE    — inverse of ONE.TWO
//   ZERO.TWO   — zero-prefix on chunk size; BE counts differently
//   TWO.ZERO   — two-byte size with zero-prefix on second chunk

import (
	"github.com/smuggled/smuggled/internal/request"
	"github.com/smuggled/smuggled/internal/config"
	"fmt"
	"net/url"

	"github.com/smuggled/smuggled/internal/report"
)

// altTerminators are the non-standard line endings to try.
// Expanded beyond the original 4 to cover space/tab-prefixed CRLF variants
// and LF+CR ordering — each can expose different parser boundaries depending
// on whether the front-end or back-end strips, ignores or counts the extra byte.
var altTerminators = []string{
	"\n",    // bare LF — RFC-non-compliant but accepted by many parsers
	"\r",    // bare CR
	"\rX",   // CR + garbage — some parsers read CR as line end, others read until LF
	"\r\r",  // double CR — two line-end candidates
	"\n\r",  // LF+CR — inverse of CRLF; confuses parsers that look for CR-first
	" \r\n", // space-prefixed CRLF — front-ends may strip the space, back-ends may not
	"\t\r\n", // tab-prefixed CRLF — same discrepancy with tab stripping
}

// chunkPayloadPair holds forward (attack) and inverted (control) payloads.
// If the inverted also times out, the server uniformly rejects both interpretations —
// this is NOT a desync signal. Mirrors Java ChunkSizeScan.PayloadPair.
type chunkPayloadPair struct {
	forward  []byte
	inverted []byte
}

// ScanChunkSizes runs all 8 chunk-size parsing discrepancy probes.
func ScanChunkSizes(target *url.URL, base []byte, cfg config.Config, rep *report.Reporter) {
	host := target.Hostname()
	if p := target.Port(); p != "" {
		host = host + ":" + p
	}
	path := target.RequestURI()
	if path == "" {
		path = "/"
	}

	method := config.EffectiveMethod(cfg, true)
	dbg(cfg, "ChunkSizes: starting, target=%s method=%s", host, method)

	builders := []struct {
		name  string
		terms []string
		build func(method, path, host, term string) chunkPayloadPair
	}{
		{"TERM.EXT", altTerminators, buildTermExtPair},
		{"EXT.TERM", altTerminators, buildExtTermPair},
		{"TERM.SPILL", append(altTerminators, "", "XX"), buildTermSpillPair},
		{"SPILL.TERM", append(altTerminators, "", "XX"), buildSpillTermPair},
		{"ONE.TWO", []string{"\n", "\r"}, buildOneTwoPair},
		{"TWO.ONE", []string{"\n", "\r"}, buildTwoOnePair},
		{"ZERO.TWO", []string{""}, buildZeroTwoPair},
		{"TWO.ZERO", []string{""}, buildTwoZeroPair},
	}

	for _, b := range builders {
		for _, term := range b.terms {
			pair := b.build(method, path, host, term)
			rep.Log("ChunkSize %s term=%q target=%s", b.name, term, host)

			_, elapsed, timedOut, err := request.RawRequest(target, pair.forward, cfg)
			if err != nil {
				dbg(cfg, "ChunkSizes [%s/%q]: error: %v", b.name, term, err)
				continue
			}
			delayed := cfg.IsDelayed(elapsed)
			if !timedOut && !delayed {
				dbg(cfg, "ChunkSizes [%s/%q]: no timeout/delay (elapsed=%v)", b.name, term, elapsed)
				continue
			}
			dbg(cfg, "ChunkSizes [%s/%q]: SIGNAL timeout=%v delayed=%v elapsed=%v — checking inverted...",
				b.name, term, timedOut, delayed, elapsed)

			// Inverted payload check (false-positive guard):
			// If the inverted payload ALSO triggers (timeout OR delay), the server
			// uniformly rejects both interpretations — the forward signal is NOT
			// specific to a desync condition. Skip to avoid false positives.
			// Mirrors Java: if (respInverted.timedOut()) { return; }
			_, invertedElapsed, invertedTimedOut, invertedErr := request.RawRequest(target, pair.inverted, cfg)
			invertedDelayed := cfg.IsDelayed(invertedElapsed)
			if invertedErr == nil && (invertedTimedOut || invertedDelayed) {
				dbg(cfg, "ChunkSizes [%s/%q]: inverted also triggered (timeout=%v delayed=%v) — FALSE POSITIVE, skipping",
					b.name, term, invertedTimedOut, invertedDelayed)
				continue
			}
			dbg(cfg, "ChunkSizes [%s/%q]: inverted OK (no timeout/delay) — confirming forward...", b.name, term)

			// Confirm forward payload consistency.
			// Must check both timeout AND delay to be consistent with initial detection.
			confirmed := 0
			for i := 0; i < cfg.ConfirmReps+2; i++ {
				_, cElapsed, to, e := request.RawRequest(target, pair.forward, cfg)
				if e == nil && (to || cfg.IsDelayed(cElapsed)) {
					confirmed++
				}
			}
			dbg(cfg, "ChunkSizes [%s/%q]: confirmed=%d/%d", b.name, term, confirmed, cfg.ConfirmReps)
			if confirmed < cfg.ConfirmReps {
				continue
			}

			displayTerm := fmt.Sprintf("%q", term)
			rep.Emit(report.Finding{
				Target:    target.String(),
				Method:      config.EffectiveMethods(cfg)[0],
				Severity:  report.SeverityConfirmed,
				Type:      "chunk-size-" + b.name,
				Technique: b.name + "/" + displayTerm,
				Description: fmt.Sprintf(
					"%s: repeated timeout with alternate terminator %s in chunk body "+
						"(inverted payload did NOT timeout — directional desync confirmed). "+
						"Front-end and back-end disagree on chunk boundary — exploitable for HRS.",
					b.name, displayTerm),
				RawProbe: request.Truncate(string(pair.forward), 512),
			})
			rep.Log("ChunkSize [!] %s/%s confirmed on %s", b.name, displayTerm, target.String())
			if cfg.ExitOnFind {
				return
			}
		}
	}
}

// ─── Payload builders ────────────────────────────────────────────────────────
// Each mirrors the exact Java payload structure from ChunkSizeScan.java.
// Now returns a chunkPayloadPair with forward (attack) and inverted (control).

func chunkHeader(method, path, host string) string {
	return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
		method, path, host)
}

// TERM.EXT: chunk extension with alternate terminator; two conflicting chunk sizes follow
//
// Forward:                    Inverted:
//   2;<term>XX\r\n              2;<term>XX\r\n
//   10\r\n                      14\r\n
//   1f\r\n                      10\r\n
//   AAAABBBBCCCC\r\n            AAAABBBBCCCCDDDD\r\n
//   0\r\n\r\n                   0\r\n\r\n
//   DDDDEEEEFFFF\r\n
//   0\r\n\r\n
func buildTermExtPair(method, path, host, term string) chunkPayloadPair {
	hdr := chunkHeader(method, path, host)
	fwd := hdr +
		"2;" + term + "XX\r\n" +
		"10\r\n" +
		"1f\r\n" +
		"AAAABBBBCCCC\r\n" +
		"0\r\n\r\n" +
		"DDDDEEEEFFFF\r\n" +
		"0\r\n\r\n"
	inv := hdr +
		"2;" + term + "XX\r\n" +
		"14\r\n" +
		"10\r\n" +
		"AAAABBBBCCCCDDDD\r\n" +
		"0\r\n\r\n"
	return chunkPayloadPair{forward: []byte(fwd), inverted: []byte(inv)}
}

// EXT.TERM
//
// Forward:                    Inverted:
//   2;<term>XX\r\n              2;<term>XX\r\n
//   22\r\n                      10\r\n
//   c\r\n                       d\r\n
//   AAAABBBBCCCC\r\n            AAAABBBBCCCCD\r\n
//   0\r\n\r\n                   0\r\n\r\n
//   DDDDEEEEFFFF\r\n
//   0\r\n\r\n
func buildExtTermPair(method, path, host, term string) chunkPayloadPair {
	hdr := chunkHeader(method, path, host)
	fwd := hdr +
		"2;" + term + "XX\r\n" +
		"22\r\n" +
		"c\r\n" +
		"AAAABBBBCCCC\r\n" +
		"0\r\n\r\n" +
		"DDDDEEEEFFFF\r\n" +
		"0\r\n\r\n"
	inv := hdr +
		"2;" + term + "XX\r\n" +
		"10\r\n" +
		"d\r\n" +
		"AAAABBBBCCCCD\r\n" +
		"0\r\n\r\n"
	return chunkPayloadPair{forward: []byte(fwd), inverted: []byte(inv)}
}

// TERM.SPILL: alternate terminator embedded inside chunk body causes a size spill
//
// Forward:                    Inverted:
//   5\r\n                       5\r\n
//   AAAAA<term>c\r\n            AAAAA<term>c\r\n
//   17\r\n                      9\r\n
//   AAAABBBB\r\n                AAAABBBBC\r\n
//   0\r\n\r\n                   0\r\n\r\n
//   CCCCDDDD\r\n
//   0\r\n\r\n
func buildTermSpillPair(method, path, host, term string) chunkPayloadPair {
	hdr := chunkHeader(method, path, host)
	fwd := hdr +
		"5\r\n" +
		"AAAAA" + term + "c\r\n" +
		"17\r\n" +
		"AAAABBBB\r\n" +
		"0\r\n\r\n" +
		"CCCCDDDD\r\n" +
		"0\r\n\r\n"
	inv := hdr +
		"5\r\n" +
		"AAAAA" + term + "c\r\n" +
		"9\r\n" +
		"AAAABBBBC\r\n" +
		"0\r\n\r\n"
	return chunkPayloadPair{forward: []byte(fwd), inverted: []byte(inv)}
}

// SPILL.TERM
//
// Forward:                    Inverted:
//   5\r\n                       5\r\n
//   AAAAA<term>1a\r\n           AAAAA<term>b\r\n
//   8\r\n                       8\r\n
//   AAAABBBB\r\n                AAAABBBB\r\n
//   0\r\n\r\n                   0\r\n\r\n
//   CCCCDDDD\r\n
//   0\r\n\r\n
func buildSpillTermPair(method, path, host, term string) chunkPayloadPair {
	hdr := chunkHeader(method, path, host)
	fwd := hdr +
		"5\r\n" +
		"AAAAA" + term + "1a\r\n" +
		"8\r\n" +
		"AAAABBBB\r\n" +
		"0\r\n\r\n" +
		"CCCCDDDD\r\n" +
		"0\r\n\r\n"
	inv := hdr +
		"5\r\n" +
		"AAAAA" + term + "b\r\n" +
		"8\r\n" +
		"AAAABBBB\r\n" +
		"0\r\n\r\n"
	return chunkPayloadPair{forward: []byte(fwd), inverted: []byte(inv)}
}

// ONE.TWO
//
// Forward:                    Inverted:
//   2\r\n                       2\r\n
//   XX<term>                    XX<term>
//   12\r\n                      12\r\n
//   XX\r\n                      XX\r\n
//   19\r\n                      b\r\n
//   XXAAAABBBB\r\n              XXXAAAABBBB\r\n
//   0\r\n\r\n                   0\r\n\r\n
//   CCCCDDDD\r\n
//   0\r\n\r\n
func buildOneTwoPair(method, path, host, term string) chunkPayloadPair {
	hdr := chunkHeader(method, path, host)
	fwd := hdr +
		"2\r\n" +
		"XX" + term +
		"12\r\n" +
		"XX\r\n" +
		"19\r\n" +
		"XXAAAABBBB\r\n" +
		"0\r\n\r\n" +
		"CCCCDDDD\r\n" +
		"0\r\n\r\n"
	inv := hdr +
		"2\r\n" +
		"XX" + term +
		"12\r\n" +
		"XX\r\n" +
		"b\r\n" +
		"XXXAAAABBBB\r\n" +
		"0\r\n\r\n"
	return chunkPayloadPair{forward: []byte(fwd), inverted: []byte(inv)}
}

// TWO.ONE
//
// Forward:                    Inverted (safe terminator):
//   2\r\n                       0\r\n
//   XX<term>                    \r\n
//   10\r\n
//   \r\n
//   AAAABBBBCCCCDD\r\n
//   0\r\n\r\n
func buildTwoOnePair(method, path, host, term string) chunkPayloadPair {
	hdr := chunkHeader(method, path, host)
	fwd := hdr +
		"2\r\n" +
		"XX" + term +
		"10\r\n" +
		"\r\n" +
		"AAAABBBBCCCCDD\r\n" +
		"0\r\n\r\n"
	inv := hdr +
		"0\r\n" +
		"\r\n"
	return chunkPayloadPair{forward: []byte(fwd), inverted: []byte(inv)}
}

// ZERO.TWO — zero-prefixed chunk size
//
// Forward:                    Inverted (safe terminator):
//   2\r\n                       0\r\n
//   XX<term>                    \r\n
//   012\r\n
//   XX\r\n
//   19\r\n
//   XXAAAABBBB\r\n
//   0\r\n\r\n
//   CCCCDDDD\r\n
//   0\r\n\r\n
func buildZeroTwoPair(method, path, host, term string) chunkPayloadPair {
	hdr := chunkHeader(method, path, host)
	fwd := hdr +
		"2\r\n" +
		"XX" + term +
		"012\r\n" +
		"XX\r\n" +
		"19\r\n" +
		"XXAAAABBBB\r\n" +
		"0\r\n\r\n" +
		"CCCCDDDD\r\n" +
		"0\r\n\r\n"
	inv := hdr +
		"0\r\n" +
		"\r\n"
	return chunkPayloadPair{forward: []byte(fwd), inverted: []byte(inv)}
}

// TWO.ZERO
//
// Forward:                    Inverted (safe terminator):
//   2\r\n                       0\r\n
//   xx<term>                    \r\n
//   010\r\n
//   \r\n
//   AAAABBBBCCCCDD\r\n
//   0\r\n\r\n
func buildTwoZeroPair(method, path, host, term string) chunkPayloadPair {
	hdr := chunkHeader(method, path, host)
	fwd := hdr +
		"2\r\n" +
		"xx" + term +
		"010\r\n" +
		"\r\n" +
		"AAAABBBBCCCCDD\r\n" +
		"0\r\n\r\n"
	inv := hdr +
		"0\r\n" +
		"\r\n"
	return chunkPayloadPair{forward: []byte(fwd), inverted: []byte(inv)}
}
