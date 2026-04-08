// Package report formats scan findings for human and machine consumption.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"smuggled.tool/pkg/scan"
)

// Format controls output style.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// Writer writes findings to an output stream.
type Writer struct {
	format  Format
	out     io.Writer
	verbose bool
}

// New creates a Writer.
func New(format Format, out io.Writer, verbose bool) *Writer {
	return &Writer{format: format, out: out, verbose: verbose}
}

// PrintScanStart prints a banner for the scan start.
func (w *Writer) PrintScanStart(url string) {
	if w.format == FormatJSON {
		return
	}
	banner := strings.Repeat("─", 60)
	fmt.Fprintf(w.out, "\n%s\n", banner)
	fmt.Fprintf(w.out, " Smuggled — HTTP Request Smuggling Scanner\n")
	fmt.Fprintf(w.out, " Target : %s\n", url)
	fmt.Fprintf(w.out, " Time   : %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w.out, "%s\n\n", banner)
}

// PrintFindings outputs findings in the configured format.
func (w *Writer) PrintFindings(findings []scan.Finding) {
	if w.format == FormatJSON {
		w.printJSON(findings)
		return
	}
	w.printText(findings)
}

// PrintScanComplete prints a summary line.
func (w *Writer) PrintScanComplete(url string, findings []scan.Finding, elapsed time.Duration) {
	if w.format == FormatJSON {
		return
	}
	confirmed := 0
	probable := 0
	for _, f := range findings {
		switch f.Severity {
		case scan.SeverityConfirmed:
			confirmed++
		case scan.SeverityProbable:
			probable++
		}
	}
	fmt.Fprintf(w.out, "\nScan complete for %s in %s\n", url, elapsed.Round(time.Millisecond))
	fmt.Fprintf(w.out, "  Findings : %d total (%d confirmed, %d probable)\n\n",
		len(findings), confirmed, probable)
}

// PrintError prints an error message.
func (w *Writer) PrintError(url string, err error) {
	if w.format == FormatJSON {
		out := map[string]any{
			"url":   url,
			"error": err.Error(),
		}
		b, _ := json.Marshal(out)
		fmt.Fprintf(w.out, "%s\n", b)
		return
	}
	fmt.Fprintf(w.out, "[ERROR] %s — %v\n", url, err)
}

// JSONReport is the top-level JSON output structure.
type JSONReport struct {
	ScannedAt string       `json:"scanned_at"`
	Version   string       `json:"version"`
	Results   []JSONResult `json:"results"`
}

// JSONResult groups findings per URL.
type JSONResult struct {
	URL      string         `json:"url"`
	Findings []JSONFinding  `json:"findings"`
	Error    string         `json:"error,omitempty"`
}

// JSONFinding is a single finding serialised for JSON output.
type JSONFinding struct {
	Type        string `json:"type"`
	Technique   string `json:"technique"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Timestamp   string `json:"timestamp"`
}

func (w *Writer) printJSON(findings []scan.Finding) {
	jf := make([]JSONFinding, 0, len(findings))
	for _, f := range findings {
		jf = append(jf, JSONFinding{
			Type:        f.Type,
			Technique:   f.Technique,
			Severity:    string(f.Severity),
			Description: f.Description,
			Evidence:    f.Evidence,
			Timestamp:   f.Timestamp.Format(time.RFC3339),
		})
	}

	result := JSONResult{
		URL:      findings[0].URL,
		Findings: jf,
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(w.out, `{"error": "marshal failed: %v"}`+"\n", err)
		return
	}
	fmt.Fprintf(w.out, "%s\n", b)
}

func (w *Writer) printText(findings []scan.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(w.out, "  No vulnerabilities found.")
		return
	}

	for _, f := range findings {
		sev := severityTag(f.Severity)
		fmt.Fprintf(w.out, "%s [%s] %s\n", sev, f.Type, f.URL)
		fmt.Fprintf(w.out, "     Technique : %s\n", f.Technique)
		fmt.Fprintf(w.out, "     Severity  : %s\n", f.Severity)
		fmt.Fprintf(w.out, "     Info      : %s\n", f.Description)
		if w.verbose {
			fmt.Fprintf(w.out, "     Evidence  :\n")
			for _, line := range strings.Split(f.Evidence, "\n") {
				fmt.Fprintf(w.out, "       %s\n", line)
			}
		}
		fmt.Fprintln(w.out)
	}
}

func severityTag(s scan.Severity) string {
	switch s {
	case scan.SeverityConfirmed:
		return "[CONFIRMED]"
	case scan.SeverityProbable:
		return "[PROBABLE] "
	default:
		return "[INFO]     "
	}
}

// PrintNoFindings prints a clean "nothing found" message for a URL.
func (w *Writer) PrintNoFindings(url string) {
	if w.format == FormatJSON {
		result := JSONResult{URL: url, Findings: []JSONFinding{}}
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintf(w.out, "%s\n", b)
		return
	}
	fmt.Fprintf(w.out, "  No smuggling vulnerabilities detected for %s\n\n", url)
}
