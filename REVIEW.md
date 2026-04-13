# Smuggled — Revisão Sistemática de Módulos, Técnicas e Payloads

> Gerado em 2026-04-13. Referência técnica completa do scanner.

---

## 1. Módulos de Scan (15 total)

### HTTP/1.1 (11 módulos)

| Módulo | Arquivo | Técnica | Sinal de Detecção |
|--------|---------|---------|-------------------|
| **CL.TE** | `clte.go` | ~71 permutações de TE | Front usa CL (trunca); back usa TE (aguarda bytes) → **TIMEOUT** |
| **TE.CL** | `tecl.go` | ~71 permutações de TE | Front usa TE (para em `0\r\n\r\n`); back usa CL (+1 byte) → **TIMEOUT** |
| **CL.0** | `cl0.go` | 12 mutações de CL | Gadget bleed (marker no response), status divergence, 400 potencial |
| **ChunkSizes** | `chunksizes.go` | 8 variantes × 4 terminadores alternativos | Terminador alternativo (`\n`,`\r`,`\rX`,`\r\r`) → discrepância de parser → **TIMEOUT** |
| **ParserDiscrepancy** | `parser.go` | 5 canários × 5 técnicas de ocultação | Header oculto injetado → front remove, back vê → **status divergence** |
| **ClientDesync** | `clientdesync.go` | CL-body-smuggle | POST com CL = tamanho do follow-up, body vazio; follow-up timeout = desync |
| **ConnectionState** | `connstate.go` | status-diff, reflect-diff | Baseline vs. reuse de conexão → divergência de status ou canário |
| **PauseDesync** | `connstate.go` (`ScanPauseDesync`) | pause-body-smuggle | Headers → pausa 6s → body; marker no follow-up = desync |
| **ImplicitZero** | `implizero.go` | GET-chunked-smuggle, HEAD-body-smuggle | GET/HEAD + TE + body → back trata body como nova request |
| **H1Tunnel** | `h1tunnel.go` | HEAD/POST/GET/OPTIONS × 3 perms TE (vanilla, nameprefix1, dualchunk) | Body contém request smugglada → resposta HTTP aninhada detectada |
| **HeaderRemoval** | `headerremoval.go` | Keep-Alive header stripping | Keep-Alive + "host" em Connection → proxy remove Host → body injeta `Host: <canário>` |

### HTTP/2 (4 módulos)

| Módulo | Arquivo | Técnica | Sinal de Detecção |
|--------|---------|---------|-------------------|
| **H2Downgrade** | `h2.go` | H2.TE-vanilla, H2.TE-crlf, H2.TE-lf, H2.CL-inject, H2.host-inject | Chunk size inflado (declara 13, envia 3) → back timeout; falha de conexão (status=0) |
| **H2CLInject** | `h2clinject.go` | H2.CL/path-inject, H2.CL/method-inject (× `cfg.Attempts`) | CRLF em `:path`/`:method` injeta `Content-Length: 0` → canário ou status diverge |
| **H2Tunnel** | `h2tunnel.go` | H2-tunnel/{GET,POST,HEAD,OPTIONS}; HeadTE/{GET,POST} × 5 perms; H2-tunnel-CL/{GET,POST,HEAD,OPTIONS} | Body contém request H1 smugglada → linha de status H1 no body H2 |
| **H2Research** | `h2research.go` | HTTP2FakePseudo, HTTP2Scheme, HTTP2DualPath, HTTP2Method, HiddenHTTP2 | Canário via CRLF em pseudo-headers; `:path` duplicado; H2 oculto detectado |

### PathCRLFInject (módulo híbrido H1+H2)

| Arquivo | Variantes |
|---------|-----------|
| `pathcrlfinject.go` | H1 + H2 × 6 variantes: hash/{single,double}, nohash/{single,double}, hash-body/{single,double}, hash-host/{single,double}, hash-lf/{single,double} |

---

## 2. Permutações de Transfer-Encoding (~71 técnicas)

### Compartilhadas (H1 + H2)
`vanilla`, `underjoin1`, `spacejoin1`, `space1`, `nameprefix1`, `nameprefix2`, `valueprefix1`, `vertwrap`, `connection`, `spjunk`, `backslash`, `spaceFF`, `unispace`, `commaCow`, `cowComma`, `contentEnc`, `quoted`, `aposed`, `dualchunk`, `lazygrep`, `0dsuffix`, `tabsuffix`, `revdualchunk`, `nested`, `encode`, `accentTE`, `accentCH`, `removed`, `get`, `options`, `head`, `range`, `qencode`, `qencodeutf`, `nel`, `nbsp`, `shy`, `shy2`

### Exclusivas H1
`nospace1`, `linewrapped1`, `doublewrapped`, `gareth1`, `badsetupCR`, `badsetupLF`, `multiCase`, `tabwrap`, `UPPERCASE`, `0dwrap`, `0dspam`, `badwrap`, `bodysplit`, `h1case`, `http1.0`

### Exclusivas H2
`http2hide`, `h2colon`, `h2auth`, `h2path`, `http2case`, `h2scheme`, `h2name`, `h2method`, `h2space`, `h2prefix`, `h2CL`

### Dinâmicas (por byte especial)
`spacefix1:N`, `prefix1:N`, `suffix1:N`, `namesuffix1:N`  
Bytes: `0x00, 0x09, 0x0b, 0x0c, 0x0d, 0x7f`

---

## 3. Mutações de Content-Length (12 técnicas)

| Nome | Exemplo de Valor Gerado |
|------|------------------------|
| CL-plus | `+17` |
| CL-minus | `-17` |
| CL-pad | `017` |
| CL-bigpad | `00000000000017` |
| CL-e | `17e0` |
| CL-dec | `17.0` |
| CL-commaprefix | `0, 17` |
| CL-commasuffix | `17, 0` |
| CL-error | header inválido antes do CL |
| CL-spacepad | `  17` (espaços leading) |
| CL-expect | `Expect: 100-continue` + CL real |
| CL-expect-obfs | `Expect: x 100-continue` (valor inválido) |

---

## 4. Gadgets do CL.0 (5 gadgets)

| Requisição Smugglada | Marker | Header-Only |
|---------------------|--------|-------------|
| `GET /wrtztrw?wrtztrw=wrtztrw HTTP/1.1` | `wrtztrw` | não |
| `GET /robots.txt HTTP/1.1` | `llow:` | não |
| `GET /favicon.ico HTTP/1.1` | `image/` | sim |
| `TRACE / HTTP/1.1` | `405 ` (espaço trailing evita falso positivo em UUIDs) | sim |
| `GET / HTTP/2.2` | `505 ` (idem) | sim |

**Seleção**: testa cada gadget diretamente; descarta se erro, timeout ou marker já na baseline. Usa primeiro viável. Fallback: TRACE.

---

## 5. Permutações do H2.CL0 (8 variantes)

| Nome | Headers Extras | Content-Length |
|------|---------------|----------------|
| `connection+expect-obfs/no-cl` | `connection: keep-alive`, `expect: x 100-continue` | suprimido (`""`) |
| `connection+expect-obfs/cl` | `connection: keep-alive`, `expect: x 100-continue` | presente |
| `connection-only/no-cl` | `connection: keep-alive` | suprimido |
| `connection-only/cl` | `connection: keep-alive` | presente |
| `expect-obfs-only/no-cl` | `expect: x 100-continue` | suprimido |
| `expect-obfs-only/cl` | `expect: x 100-continue` | presente |
| `expect-standard/no-cl` | `expect: 100-continue` | suprimido |
| `expect-standard/cl` | `expect: 100-continue` | presente |

> Regra H2: se body vazio, `content-length` é suprimido por padrão (DATA frames delimitam o body — RFC 9113 §8.1.2.6). Sentinel `""` force-suprime mesmo com body.

---

## 6. Técnicas de Ocultação de Header (ParserDiscrepancy)

### Canários Testados (3 + research)
1. `Host: foo/bar` — shouldBlock=true
2. `Content-Length: Z` — shouldBlock=true  
3. `Host: <hostname>` — shouldBlock=false
4. `Content-Length: 5` — shouldBlock=true (research mode)

### Técnicas de Ocultação (5)
| Nome | Mecanismo |
|------|-----------|
| `hideSpace` | Espaço trailing no nome: `Content-Length : Z` |
| `hideTab` | Tab trailing no nome: `Content-Length\t: Z` |
| `hideWrap` | Line folding obsoleto: `Content-Length: \r\n Z` |
| `hideHop` | Marcado como hop-by-hop via `Connection:` |
| `hideLpad` | Espaço no início da próxima linha: `X-Junk: x\r\n Content-Length: Z` |

---

## 7. Variantes de PathCRLF (20 total)

Cada variante existe em H1 e H2 (`:path` override), com encoding simples (`%0d%0a`) ou duplo (`%250d%250a`):

| Família | Payload Injetado | Notas |
|---------|-----------------|-------|
| `hash` | `CRLF` + `Content-Length: 100\r\nFoo: x` | Com fragmento `#` |
| `nohash` | idem | Sem fragmento |
| `hash-body` | idem no path body | — |
| `hash-host` | Sobrescreve `Host:` | — |
| `hash-lf` | Somente `\n` (sem `\r`) | LF-only |

---

## 8. Técnicas H2 Research (5)

| Nome | Pseudo-header Alvo | Vetor |
|------|-------------------|-------|
| `HTTP2FakePseudo` | `:path` | Injeta `:path : /<canário>` via `x: x\r\n:path : ...` |
| `HTTP2Scheme` | `:scheme` | Injeta `http://<host>/<canário>?` |
| `HTTP2DualPath` | `:path` duplicado | Testa 3 ordenações; divergência de status = vuln |
| `HTTP2Method` | `:method` | Injeta `GET http://<host>/<canário>` |
| `HiddenHTTP2` | TLS ALPN | Detecta H2 oculto (H1 normal, H2 via ALPN h2) |

---

## 9. Pipeline de Request

### Construção (H1)
| Função | Descrição |
|--------|-----------|
| `BuildBaseRequest()` | GET/POST mínimo (UA, Accept-Encoding: identity, CL/CT opcionais) |
| `BuildRequestForMethod()` | Igual com método explícito |
| `UpgradeToBodyMethod()` | GET/HEAD → POST se body requerido e !ForceMethod |
| `BuildKeepAliveRequest()` | POST com `Connection: keep-alive`, CL=0 |
| `BuildGETRequest()` | GET mínimo de uma request-line |
| `InjectExtraHeaders()` | Merge de `cfg.ExtraHeaders` + `cfg.Cookies` no raw H1 |

### Mutação de Payload
| Função | O que faz |
|--------|-----------|
| `SetBody()` | Substitui bytes após `\r\n\r\n` |
| `SetContentLength()` | Adiciona/substitui header CL |
| `SetConnection()` | Adiciona/substitui `Connection:` |
| `AddTE()` | Adiciona `Transfer-Encoding: chunked` se ausente |
| `BypassCLFix()` | `Content-Length` → `content-length` (bypass de normalização) |
| `ApplyTE()` | Aplica permutação TE pelo nome |
| `ApplyCL()` | Aplica mutação CL pelo nome + valor |

### Envio de Request (H1)
| Função | Comportamento |
|--------|--------------|
| `RawRequest()` | Abre conexão → envia → recebe com timeout → retorna `(resp, elapsed, timedOut, err)` |
| `SendNoRecv()` | Abre conexão → envia → fecha (sem leitura) |
| `LastByteSyncProbe()` | Probe conn (envia tudo menos 1 byte) + smuggle conn (full send) + byte final → recv |
| `ProbeH1()` | Connectivity check (GET + `Connection: close`) |
| `ProbeH2()` | TLS dial com ALPN `[h2, http/1.1]` → verifica `NegotiatedProtocol` |

### Envio H2
| Função | Comportamento |
|--------|--------------|
| `h2RawRequest()` | Encoda HPACK → envia HEADERS+DATA → lê resposta |
| `h2AttackAndProbe()` | Stream 1 (attack) + Stream 3 (probe) na mesma conexão multiplexada |
| `ExtraH2Headers()` | Converte `cfg.ExtraHeaders` + cookies para map H2 |

---

## 10. Sinais de Detecção (7 tipos)

| Sinal | Módulos | Critério |
|-------|---------|---------|
| **Hard timeout** | CL.TE, TE.CL, ChunkSizes | Sem resposta após `cfg.Timeout` |
| **Delayed response** | Todos com calibração | `elapsed > cfg.DelayThreshold` (mediana + 3s floor) |
| **Suspicious response** | CL.TE, TE.CL | Status 400/405 + "Unrecognised"/"GPOST"/"Invalid method" |
| **Gadget bleed** | CL.0 | Marker do gadget aparece na resposta da probe |
| **Status divergence** | CL.0, ConnState, H2CL, Parser | `probeStatus != baselineStatus` |
| **Nested H1 response** | H1Tunnel, H2Tunnel | `HTTP/1.x \d\d\d` detectado no body da resposta |
| **H2 body suspicion** | H2Downgrade, H2Tunnel | "unrecognised"/"invalid method"/"bad request" no DATA body |

---

## 11. Flags / Configuração

### Flags Principais

| Flag | Tipo | Default | Descrição |
|------|------|---------|-----------|
| `-u / --url` | string | — | URL alvo única |
| `-f / --urls-file` | string | — | Arquivo com URLs (uma por linha) |
| `-t / --timeout` | int | 10 | Timeout de request (segundos) |
| `-w / --workers` | int | 5 | Workers concorrentes |
| `-v / --verbose` | bool | false | Output verboso |
| `--debug` | int | 0 | Nível de debug: 1=resumo probe, 2=dump raw completo |
| `-j / --json` | bool | false | Output JSON (um finding por linha) |
| `-o / --output` | string | — | Salvar output em arquivo |
| `-p / --proxy` | string | — | URL de proxy HTTP |
| `--skip-tls-verify` | bool | false | Ignorar verificação TLS |
| `-c / --confirm` | int | 3 | Confirmações necessárias (ConfirmReps) |
| `-m / --method` | []string | — | Método(s) HTTP (POST, GET, HEAD…) |
| `--force-method` | bool | false | Forçar método mesmo em body probes |
| `-x / --exit` | bool | false | Sair no primeiro finding (cross-module) |
| `-C / --calibrate` | bool | false | Auto-calibrar threshold de timing |
| `--http1` | bool | false | Apenas scans H1 |
| `--http2` | bool | false | Apenas scans H2 |
| `-a / --all` | bool | false | Habilitar todos os módulos + research |
| `--research` | bool | false | Probes H2 research |
| `--techniques` | []string | — | Lista de técnicas específicas |
| `--modules` | []string | — | Lista de módulos específicos |
| `-H / --header` | []string | — | Headers customizados (repetível) |
| `--attempts` | int | 5 | Ciclos attack+probe (CL.0, H2.CL0, H2.CL) |
| `--canary-path` | string | `/smuggled-canary-xzyw` | Path canário para gadget detection |

### Flags Skip

`--skip-clte`, `--skip-tecl`, `--skip-h2`, `--skip-parser`, `--skip-client-desync`, `--skip-pause`, `--skip-implicit`, `--skip-conn-state`, `--skip-cl0`, `--skip-chunk-sizes`, `--skip-h1-tunnel`, `--skip-h2-tunnel`, `--skip-header-removal`, `--skip-path-crlf`

---

## 12. Output / Reporter

### Formatos

**Plain text:**
```
[CONFIRMED] https://target.com — CL.TE via POST (vanilla)
  Front-end uses CL, back-end uses TE...
```

**JSON (um objeto por linha):**
```json
{
  "title": "HTTP Request Smuggling — CL.TE via POST (vanilla)",
  "status": "open",
  "severity": "critical",
  "template": "hrs-clte",
  "cwe": "CWE-444",
  "owasp": "A07:2021",
  "technique": "vanilla",
  "requests": [["raw_probe"], ["raw_probe", "raw_response"]]
}
```

### Mapeamento de Severidade

| Nível | Severidade JSON | Template |
|-------|----------------|----------|
| CONFIRMED | critical | hrs-clte / hrs-tecl / hrs-cl0 / hrs-h2-* |
| PROBABLE | high | idem |
| INFO | medium | hrs-hidden-h2 / hrs-timing / etc. |

---

## 13. Estatísticas Resumidas

| Categoria | Quantidade |
|-----------|-----------|
| Módulos de scan | 15 (11 H1 + 4 H2) |
| Permutações TE (H1+H2) | ~71 estáticas + dinâmicas por byte especial |
| Mutações CL | 12 |
| Gadgets CL.0 | 5 |
| Permutações H2.CL0 | 8 (no-cl / cl × 4 header combos) |
| Técnicas de ocultação (Parser) | 5 |
| Variantes PathCRLF | 20 (H1+H2 × 10 famílias) |
| Técnicas H2 Research | 5 |
| Sinais de detecção | 7 tipos distintos |
| Flags de configuração | ~40 |
| Formatos de output | 2 (plain text, JSON) |
| **Payloads totais estimados** | **~200+** |

---

## 14. Estrutura de Arquivos

```
cmd/
  root.go                  — CLI entry point, flags, cfg build

internal/
  config/
    config.go              — Config struct, EffectiveMethods, IsDelayed

  permute/
    desync.go              — ApplyTE(), ApplyCL(), All() — 71+ técnicas

  request/
    request.go             — RawRequest, SendNoRecv, LastByteSyncProbe,
                             ProbeH1, ProbeH2, helpers de parse

  scan/
    scanner.go             — Orchestrador: probe → calibrate → runModules
    debug.go               — Wrapper de debug com prefixo de scope
    clte.go                — ScanCLTE
    tecl.go                — ScanTECL
    cl0.go                 — ScanCL0, ScanH2CL0, gadgets, last-byte-sync
    h2.go                  — ScanH2Downgrade, h2CLSmuggle
    h2clinject.go          — ScanH2CLInject
    h2tunnel.go            — ScanH2Tunnel, h2RawRequest, h2AttackAndProbe,
                             h2DumpRequest, h2DumpResponse
    h2research.go          — ScanH2Research
    chunksizes.go          — ScanChunkSizes
    parser.go              — ScanParserDiscrepancy
    clientdesync.go        — ScanClientDesync
    connstate.go           — ScanConnectionState, ScanPauseDesync
    implizero.go           — ScanImplicitZero
    h1tunnel.go            — ScanH1Tunnel
    headerremoval.go       — ScanHeaderRemoval
    pathcrlfinject.go      — ScanPathCRLFInject

  report/
    report.go              — Reporter, Emit, Found, JSON/plain output
```
