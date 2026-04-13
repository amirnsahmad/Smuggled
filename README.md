# Smuggled

**HTTP Request Smuggling Scanner** — Go port of [PortSwigger's HTTP Request Smuggler](https://github.com/PortSwigger/http-request-smuggler) Java plugin, with expanded payload coverage derived from [smuggler](https://github.com/amirnsahmad/smuggler) and [CLZero](https://github.com/Moopinger/CLZero).

> For authorized penetration testing and security research only.

---

## Features

- **15 scan modules** covering every major HRS variant
- **~183 Transfer-Encoding permutations** (CL.TE / TE.CL)
- **148 Content-Length mutations** (CL.0)
- **Full HTTP/2 → HTTP/1.1 downgrade detection** (H2.CL, H2.TE, H2.CL0, H2 tunnel)
- Auto-calibrated timing, confirmation loops, false-positive guards
- JSON output, custom headers/cookies, proxy support, concurrent workers

---

## Installation

```bash
git clone https://github.com/amirnsahmad/Smuggled
cd Smuggled
go build -o smuggler .
```

**Requirements:** Go 1.21+

---

## Quick Start

```bash
# Scan a single target
./smuggler scan https://example.com

# Scan with verbose output and debug dumps
./smuggler scan https://example.com --verbose --debug 2

# Scan from a file, 20 workers, JSON output
./smuggler scan -f targets.txt -w 20 --json -o results.jsonl

# HTTP/1.1 only, skip slow modules, exit on first finding
./smuggler scan https://example.com --http1 --skip-pause --skip-conn-state -x

# Full scan — all modules, all methods, research probes
./smuggler scan https://example.com --all
```

---

## Scan Modules

### HTTP/1.1

| Module | Flag | Technique | Detection |
|--------|------|-----------|-----------|
| **CL.TE** | `--skip-clte` | ~183 TE permutations | Timeout / delay / suspicious 400 |
| **TE.CL** | `--skip-tecl` | ~183 TE permutations | Timeout / delay / suspicious 400 |
| **CL.0** | `--skip-cl0` | 148 CL mutations | Gadget bleed / status divergence |
| **ChunkSizes** | `--skip-chunk-sizes` | 8 variants × 7 terminators | Timeout on alt terminator |
| **ParserDiscrepancy** | `--skip-parser` | 5 hide techniques × 3 canaries | Status divergence |
| **ClientDesync** | `--skip-client-desync` | CL body smuggle | Follow-up timeout |
| **ConnectionState** | `--skip-conn-state` | Status/reflect diff | Status divergence |
| **PauseDesync** | `--skip-pause` | Mid-body TCP pause | Canary / status divergence |
| **ImplicitZero** | `--skip-implicit` | GET/HEAD + chunked body | Follow-up 400/405 or method reflection |
| **H1Tunnel** | `--skip-h1-tunnel` | 4 methods × 12 TE perms | Nested HTTP response / timeout |
| **HeaderRemoval** | `--skip-header-removal` | Keep-Alive hop-by-hop stripping | Status/canary divergence |
| **PathCRLFInject** | `--skip-path-crlf` | 20 CRLF-in-path variants | Timeout from injected CL:100 |

### HTTP/2

| Module | Flag | Technique | Detection |
|--------|------|-----------|-----------|
| **H2Downgrade** | `--skip-h2` | H2.TE, H2.CL, H2.host-inject | Timeout / connection failure |
| **H2CLInject** | `--skip-h2` | CRLF in `:path` / `:method` | Canary reflection / status divergence |
| **H2Tunnel** | `--skip-h2-tunnel` | H2-tunnel, HeadScanTE, H2-tunnel-CL | Nested H1 response in DATA frame |
| **H2Research** | `--research` | FakePseudo, Scheme, DualPath, Method, HiddenH2 | Canary reflection / status divergence |

---

## Flags

```
TARGETING
  -u, --url string          Single target URL
  -f, --urls-file string    File with one URL per line (stdin also supported)
  -w, --workers int         Concurrent workers (default 5)

PROTOCOL
      --http1               HTTP/1.1 modules only
      --http2               HTTP/2 modules only
  -m, --method strings      HTTP method(s): -m POST,GET,HEAD (default POST)
      --force-method        Force method even on body-bearing probes

TIMING & ACCURACY
  -t, --timeout int         Request timeout seconds (default 10)
  -C, --calibrate           Auto-calibrate delay threshold from baseline
  -c, --confirm int         Confirmations required (default 3)
      --attempts int        Attack+probe cycles for CL.0/H2 (default 5)

MODULES
      --modules strings     Run specific modules only (ignores --skip-*)
      --techniques strings  Run specific techniques only
  -a, --all                 All modules + research + POST,GET,HEAD
      --research            Enable H2 research probes
      --skip-clte / --skip-tecl / --skip-cl0 / ...

OUTPUT
  -v, --verbose             Verbose logging
      --debug int           1=probe summary  2=full raw request/response dumps
  -j, --json                JSON output (one finding per line)
  -o, --output string       Write output to file
  -x, --exit                Stop after first finding (cross-module)

NETWORK
  -p, --proxy string        HTTP proxy (e.g. http://127.0.0.1:8080)
      --skip-tls-verify     Skip TLS certificate verification
  -H, --header stringArray  Custom header: -H "Authorization: Bearer token"
      --canary-path string  Canary path for gadget detection (default /smuggled-canary-xzyw)
```

---

## Permutation Coverage

### Transfer-Encoding (~183 techniques)

Covers every obfuscation strategy from PortSwigger's DesyncBox.java, plus the full dynamic byte sets from [smuggler](https://github.com/amirnsahmad/smuggler):

| Family | Example | Count |
|--------|---------|-------|
| Static named | `Transfer_Encoding`, `Transfer-Encoding : `, `"chunked"`, … | ~40 |
| `spacefix1` (midspace) | `Transfer-Encoding:<byte>chunked` | 13 |
| `prefix1` (value prefix) | `Transfer-Encoding: <byte>chunked` | 13 |
| `suffix1` (endspace) | `Transfer-Encoding: chunked<byte>` | 13 |
| `namesuffix1` (postspace) | `Transfer-Encoding<byte>: chunked` | 13 |
| `TE-prespace` | `<byte>Transfer-Encoding: chunked` | 13 |
| `TE-xprespace` | `X: X<byte>Transfer-Encoding: chunked` | 13 |
| `TE-endspacex` | `Transfer-Encoding: chunked<byte>X: X` | 13 |
| `TE-rxprespace` | `X: X\r<byte>Transfer-Encoding: chunked` | 13 |
| `TE-xnprespace` | `X: X<byte>\nTransfer-Encoding: chunked` | 13 |
| `TE-endspacerx` | `Transfer-Encoding: chunked\r<byte>X: X` | 13 |
| `TE-endspacexn` | `Transfer-Encoding: chunked<byte>\nX: X` | 13 |

Special bytes: `0x01 0x04 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x1f 0x20 0x7f 0xa0 0xff`

List all techniques:
```bash
./smuggler techniques
```

### Content-Length (148 mutations)

Covers all [CLZero](https://github.com/Moopinger/CLZero) mutations plus dual-CL header attacks:

| Category | Examples |
|----------|---------|
| Arithmetic | `+<n>`, `-<n>`, `<n>e0`, `<n>.0`, `<n>-0`, `<n>aa` |
| Padding | `0<n>`, `00000000000<n>` |
| Comma tricks | `0, <n>`, `<n>, 0` |
| Name obfuscation | `Content_Length:`, `Content Length:`, ` Content-Length:` |
| Separator tricks | `Content-Length\t: `, `Content-Length\t:\t`, `Content-Length : ` |
| Dual headers | `Content-Length: 0\r\nContent-Length: <n>` (RFC 7230 §3.3.2) |
| Expect bypass | `Expect: 100-continue`, `Expect: x 100-continue` |
| Dynamic byte families | `CL-midspace`, `CL-postspace`, `CL-prespace`, `CL-endspace`, `CL-xprespace`, `CL-endspacex`, `CL-rxprespace`, `CL-xnprespace`, `CL-endspacerx`, `CL-endspacexn` × 13 bytes |

### CL.0 Gadgets

Gadgets are probed in order; the first that produces a distinctive, non-baseline response is used:

1. `GET /smuggled-canary-xzyw HTTP/1.1` — canary path echoed in 404 pages *(dynamic, highest priority)*
2. `GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1` — unique path reflection
3. `GET /robots.txt HTTP/1.1` — looks for `llow:` (Allow header)
4. `GET /favicon.ico HTTP/1.1` — looks for `image/` in Content-Type
5. `TRACE / HTTP/1.1` — looks for `405 ` (Method Not Allowed)
6. `GET / HTTP/2.2` — looks for `505 ` (HTTP Version Not Supported)

---

## Output Formats

### Plain text
```
[CONFIRMED] https://example.com — CL.TE via POST (nameprefix1)
  Front-end uses Content-Length; back-end uses Transfer-Encoding.
```

### JSON (`--json`)
```json
{
  "title": "HTTP Request Smuggling — CL.TE via POST (nameprefix1)",
  "status": "open",
  "severity": "critical",
  "template": "hrs-clte",
  "cwe": "CWE-444",
  "owasp": "A07:2021",
  "technique": "nameprefix1",
  "requests": [["<raw probe>"]],
  "timestamp": "2026-04-13T..."
}
```

Severity mapping: `CONFIRMED` → `critical` | `PROBABLE` → `high` | `INFO` → `medium`

---

## Examples

```bash
# Scan through Burp Suite proxy, full debug
./smuggler scan https://example.com -p http://127.0.0.1:8080 --debug 2

# CL.0 only, 10 attempts, custom canary path
./smuggler scan https://example.com --modules cl0 --attempts 10 \
  --canary-path /api/not-found-xyz

# Single TE technique
./smuggler scan https://example.com --techniques nameprefix1

# H2 only with research probes
./smuggler scan https://example.com --http2 --research

# Authenticated scan
./smuggler scan https://example.com \
  -H "Authorization: Bearer eyJhbGci..." \
  -H "Cookie: session=abc123"

# Pipe URLs from subfinder
subfinder -d example.com -silent | httpx -silent | ./smuggler scan --workers 20 --json
```

---

## Detection Signals

| Signal | Modules |
|--------|---------|
| Hard timeout | CL.TE, TE.CL, ChunkSizes, PathCRLF |
| Delayed response | All (with `--calibrate`) |
| Suspicious 400/405 | CL.TE, TE.CL (+ "GPOST"/"Unrecognised") |
| Gadget bleed | CL.0, H2.CL0 — marker reflected in probe response |
| Status divergence | CL.0, H2.CL, ConnState, Parser, ImplicitZero |
| Nested H1 response | H1Tunnel, H2Tunnel — `HTTP/1.x` line inside response body |
| Canary reflection | H2Research, HeaderRemoval, ConnState |

---

## References

- [PortSwigger: HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks)
- [PortSwigger: HTTP/1 Must Die](https://portswigger.net/research/http1-must-die)
- [PortSwigger: Funky Chunks](https://w4ke.info/2025/06/18/funky-chunks.html)
- [HTTP Request Smuggler (Java)](https://github.com/PortSwigger/http-request-smuggler)
- [smuggler (Python)](https://github.com/amirnsahmad/smuggler)
- [CLZero (Python)](https://github.com/Moopinger/CLZero)
- [CWE-444: Inconsistent Interpretation of HTTP Requests](https://cwe.mitre.org/data/definitions/444.html)

---

## License

For authorized security testing only. Do not use against systems you do not own or have explicit permission to test.
