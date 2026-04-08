// Package report handles output formatting for Smuggled findings.
// Supports plain-text (human-readable) and JSON (pipeline-friendly) modes.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Severity classifies how certain a finding is.
type Severity string

const (
	SeverityConfirmed = Severity("CONFIRMED") // timeout + status diff confirmed
	SeverityProbable  = Severity("PROBABLE")  // single timeout signal
	SeverityInfo      = Severity("INFO")      // parser discrepancy / unusual behaviour
)

// Finding represents a single detected vulnerability or interesting behaviour.
type Finding struct {
	Time        time.Time `json:"time"`
	Target      string    `json:"target"`
	Severity    Severity  `json:"severity"`
	Type        string    `json:"type"`        // e.g. "CL.TE", "TE.CL", "H2.TE", "parser-discrepancy"
	Technique   string    `json:"technique"`   // permutation name that triggered it
	Description string    `json:"description"` // human-readable summary
	Evidence    string    `json:"evidence,omitempty"`
	RawProbe    string    `json:"raw_probe,omitempty"`
}

// Reporter writes findings to an output writer in either text or JSON format.
type Reporter struct {
	mu     sync.Mutex
	out    io.Writer
	jsonFmt bool
	verbose bool
}

// New creates a new Reporter.
func New(out io.Writer, jsonFormat, verbose bool) *Reporter {
	return &Reporter{out: out, jsonFmt: jsonFormat, verbose: verbose}
}

// Emit records and prints a finding.
func (r *Reporter) Emit(f Finding) {
	f.Time = time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.jsonFmt {
		b, _ := json.Marshal(f)
		fmt.Fprintln(r.out, string(b))
		return
	}

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

// Log prints a debug/info line (only when verbose).
func (r *Reporter) Log(format string, args ...any) {
	if !r.verbose {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.out, "\033[2m[DBG] "+format+"\033[0m\n", args...)
}

// Progress prints a progress line unconditionally (goes to stderr-like formatting).
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
