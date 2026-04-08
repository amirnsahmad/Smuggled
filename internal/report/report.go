// Package report handles output formatting for Smuggled findings.
// Supports plain-text (human-readable) and JSON (schema-compatible) modes.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ─── Severity ─────────────────────────────────────────────────────────────────

// Severity classifies how certain a finding is.
type Severity string

const (
	SeverityConfirmed = Severity("CONFIRMED") // timeout confirmed multiple times
	SeverityProbable  = Severity("PROBABLE")  // single strong signal
	SeverityInfo      = Severity("INFO")      // anomalous behaviour, needs verification
)

// severityToVuln maps internal severity to vulnerability severity level.
func severityToVuln(s Severity) string {
	switch s {
	case SeverityConfirmed:
		return "critical"
	case SeverityProbable:
		return "high"
	default:
		return "medium"
	}
}

// ─── Finding (internal) ──────────────────────────────────────────────────────

// Finding is the internal representation of a detected issue.
type Finding struct {
	Time        time.Time
	Target      string
	Severity    Severity
	Type        string   // "CL.TE", "TE.CL", "H2.CL", "parser-discrepancy", etc.
	Technique   string   // permutation that triggered it
	Description string
	Evidence    string
	RawProbe    string // raw HTTP request bytes sent
	RawResponse string // raw HTTP response bytes received (if available)
}

// ─── JSON output schema ───────────────────────────────────────────────────────

// VulnReport is the JSON output format, matching the target schema.
type VulnReport struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Status      string     `json:"status"`
	Severity    string     `json:"severity"`
	Asset       []string   `json:"asset"`
	Template    string     `json:"template"`
	Source      string     `json:"source"`
	CWE         string     `json:"cwe"`
	OWASP       string     `json:"owasp"`
	References  []string   `json:"references"`
	Remediation string     `json:"remediation"`
	Requests    [][]string `json:"requests"`
	// Extra fields specific to smuggling
	Technique string `json:"technique"`
	Timestamp string `json:"timestamp"`
}

// toVulnReport converts a Finding to the output JSON schema.
func toVulnReport(f Finding) VulnReport {
	meta := metaForType(f.Type)

	// Extract hostname from target URL for asset field
	asset := extractHost(f.Target)

	// Build title
	title := fmt.Sprintf("HTTP Request Smuggling — %s", f.Type)
	if f.Technique != "" {
		title = fmt.Sprintf("%s (%s)", title, f.Technique)
	}

	// Build requests array: [[probe, response]]
	requests := buildRequestPairs(f)

	return VulnReport{
		Title:       title,
		Description: buildDescription(f, meta),
		Status:      "open",
		Severity:    severityToVuln(f.Severity),
		Asset:       []string{asset},
		Template:    meta.template,
		Source:      "smuggled",
		CWE:         meta.cwe,
		OWASP:       meta.owasp,
		References:  meta.references,
		Remediation: meta.remediation,
		Requests:    requests,
		Technique:   f.Technique,
		Timestamp:   f.Time.UTC().Format(time.RFC3339),
	}
}

// ─── Per-type metadata ────────────────────────────────────────────────────────

type typeMeta struct {
	template    string
	cwe         string
	owasp       string
	references  []string
	remediation string
}

// metaForType returns the static metadata for a given vulnerability type.
func metaForType(t string) typeMeta {
	switch {
	case t == "CL.TE":
		return typeMeta{
			template: "hrs-clte",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/web-security/request-smuggling",
				"https://portswigger.net/research/http-desync-attacks-what-happened-next",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Normalise o cabeçalho Transfer-Encoding no front-end antes de repassar ao back-end. " +
				"Desabilite suporte a chunked encoding no front-end ou configure o proxy para rejeitar " +
				"requests com ambos Content-Length e Transfer-Encoding presentes. " +
				"Prefira HTTP/2 end-to-end para eliminar a classe de vulnerabilidade.",
		}

	case t == "TE.CL":
		return typeMeta{
			template: "hrs-tecl",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/web-security/request-smuggling/exploiting",
				"https://portswigger.net/research/http-desync-attacks-what-happened-next",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Configure o back-end para priorizar Transfer-Encoding sobre Content-Length, " +
				"ou normalize headers no front-end. Rejeite requests ambíguos (com ambos CL e TE). " +
				"Prefira HTTP/2 end-to-end.",
		}

	case t == "CL.0" || t == "CL.0-potential":
		return typeMeta{
			template: "hrs-cl0",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/research/browser-powered-desync-attacks",
				"https://portswigger.net/research/http1-must-die",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Servidores que tratam implicitamente CL=0 em requests com body devem ser " +
				"configurados para rejeitar o request ou processar o body completo. " +
				"Desabilite Content-Length mutations no proxy front-end.",
		}

	case strings.HasPrefix(t, "H2.TE") || strings.HasPrefix(t, "H2.CL") || t == "H2-tunnel" || t == "H2.TE-tunnel":
		return typeMeta{
			template: "hrs-h2-downgrade",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/research/http2",
				"https://portswigger.net/web-security/request-smuggling/advanced/http2-exclusive-vectors",
				"https://portswigger.net/research/browser-powered-desync-attacks",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Use HTTP/2 end-to-end (sem downgrade para HTTP/1.1 no back-end). " +
				"Se o downgrade for necessário, sanitize todos os headers HTTP/2 antes da reescrita: " +
				"rejeite headers com CRLF nos valores, remova pseudo-headers não-padrão e " +
				"normalize Transfer-Encoding/Content-Length no processo de tradução.",
		}

	case t == "parser-discrepancy":
		return typeMeta{
			template: "hrs-parser-discrepancy",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/research/http1-must-die",
				"https://portswigger.net/web-security/request-smuggling/browser-powered",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Garanta que front-end e back-end utilizam o mesmo parser HTTP. " +
				"Configure o front-end para rejeitar headers com line-folding, null bytes, " +
				"ou outros formatos não-canônicos. Considere migrar para HTTP/2 end-to-end.",
		}

	case t == "client-desync":
		return typeMeta{
			template: "hrs-client-desync",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/research/browser-powered-desync-attacks",
				"https://portswigger.net/web-security/request-smuggling/browser-powered",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Rejeite requests POST com Content-Length maior que o body enviado. " +
				"Configure o servidor para fechar conexões após requests incompletos em vez de aguardar. " +
				"Adicione SameSite=Strict em cookies de sessão para reduzir impacto de ataques browser-powered.",
		}

	case strings.HasPrefix(t, "chunk-size-"):
		return typeMeta{
			template: "hrs-chunk-size",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://w4ke.info/2025/06/18/funky-chunks.html",
				"https://portswigger.net/research/http1-must-die",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Normalize terminadores de linha em chunk bodies para CRLF canônico antes " +
				"de repassar ao back-end. Rejeite chunks com extensões contendo caracteres de controle. " +
				"Considere desabilitar chunked encoding no front-end e usar Content-Length fixo.",
		}

	case t == "H1-tunnel":
		return typeMeta{
			template: "hrs-h1-tunnel",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/research/http1-must-die",
				"https://portswigger.net/web-security/request-smuggling/advanced",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Não repasse o body de requests HEAD/OPTIONS para o back-end. " +
				"Ignore headers X-HTTP-Method-Override e similares ou valide-os rigorosamente. " +
				"Configure o proxy para normalizar métodos antes do forwarding.",
		}

	case t == "pause-desync" || t == "connection-state":
		return typeMeta{
			template: "hrs-timing",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/research/http-desync-attacks-what-happened-next",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Configure o proxy para não fazer buffer parcial de requests. " +
				"Defina timeouts agressivos para requests incompletos. " +
				"Use HTTP/2 end-to-end.",
		}

	case t == "header-removal":
		return typeMeta{
			template: "hrs-header-removal",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/web-security/request-smuggling",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Não use o header Keep-Alive para controlar remoção de headers HTTP. " +
				"Configure o proxy para ignorar ou rejeitar o header Keep-Alive em requests de clientes.",
		}

	case t == "implicit-zero-CL":
		return typeMeta{
			template: "hrs-implicit-zero",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/research/browser-powered-desync-attacks",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Rejeite GET/HEAD requests que contenham body. " +
				"Não trate ausência de Content-Length como CL=0 implícito quando o método " +
				"normalmente não carrega body.",
		}

	default:
		return typeMeta{
			template: "hrs-generic",
			cwe:      "CWE-444",
			owasp:    "A07:2021",
			references: []string{
				"https://portswigger.net/web-security/request-smuggling",
				"https://cwe.mitre.org/data/definitions/444.html",
			},
			remediation: "Garanta que front-end e back-end interpretam os limites de requests HTTP " +
				"de forma idêntica. Prefira HTTP/2 end-to-end e desabilite chunked encoding ambíguo.",
		}
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func buildDescription(f Finding, meta typeMeta) string {
	base := f.Description
	if f.Evidence != "" {
		base = base + "\n\nEvidência técnica: " + f.Evidence
	}
	return base
}

func buildRequestPairs(f Finding) [][]string {
	// Always return an empty array (never null in JSON)
	if f.RawProbe == "" {
		return [][]string{}
	}
	pair := []string{f.RawProbe}
	if f.RawResponse != "" {
		pair = append(pair, f.RawResponse)
	} else if f.Evidence != "" {
		// Use evidence as a stand-in for the response when no raw bytes are available
		pair = append(pair, f.Evidence)
	}
	return [][]string{pair}
}

func extractHost(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return target
	}
	return u.Hostname()
}

// ─── Reporter ─────────────────────────────────────────────────────────────────

// Reporter writes findings to an output writer.
type Reporter struct {
	mu      sync.Mutex
	out     io.Writer
	jsonFmt bool
	verbose bool
}

// New creates a new Reporter.
func New(out io.Writer, jsonFormat, verbose bool) *Reporter {
	return &Reporter{out: out, jsonFmt: jsonFormat, verbose: verbose}
}

// Emit records and prints a finding immediately.
func (r *Reporter) Emit(f Finding) {
	f.Time = time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.jsonFmt {
		report := toVulnReport(f)
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(r.out, `{"error": "marshal failed: %v"}`+"\n", err)
			return
		}
		fmt.Fprintln(r.out, string(b))
		return
	}

	// Plain text output
	color := colorForSeverity(f.Severity)
	reset := "\033[0m"
	fmt.Fprintf(r.out, "%s[%s]%s %s — %s (%s) via technique=%s\n",
		color, f.Severity, reset,
		f.Target, f.Type, f.Description, f.Technique)

	if r.verbose && f.Evidence != "" {
		for _, line := range strings.Split(f.Evidence, "\n") {
			fmt.Fprintf(r.out, "  %s\n", line)
		}
	}
}

// Log prints a debug line (only when verbose).
func (r *Reporter) Log(format string, args ...any) {
	if !r.verbose {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.out, "\033[2m[DBG] "+format+"\033[0m\n", args...)
}

// Progress prints a progress line unconditionally.
func (r *Reporter) Progress(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.out, "[*] "+format+"\n", args...)
}

func colorForSeverity(s Severity) string {
	switch s {
	case SeverityConfirmed:
		return "\033[1;31m" // bold red
	case SeverityProbable:
		return "\033[1;33m" // bold yellow
	default:
		return "\033[1;34m" // bold blue
	}
}
