package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"smuggled.tool/pkg/report"
	"smuggled.tool/pkg/scan"
)

const version = "1.0.0"

var (
	flagURL              string
	flagURLsFile         string
	flagTimeout          int
	flagWorkers          int
	flagVerbose          bool
	flagJSON             bool
	flagOutput           string
	flagProxy            string
	flagSkipH2           bool
	flagSkipParser       bool
	flagSkipClientDesync bool
	flagSkipPause        bool
	flagConfirmRounds    int
	flagTechniques       []string
	flagVersion          bool
)

// RootCmd is the entry-point cobra command.
var RootCmd = &cobra.Command{
	Use:   "smuggled [flags] [url]",
	Short: "Smuggled — HTTP Request Smuggling Scanner",
	Long: `Smuggled is a standalone CLI scanner for HTTP Request Smuggling vulnerabilities.
It detects CL.TE, TE.CL, parser discrepancy, client-side desync,
implicit-zero CL, pause desync, and H2 downgrade attacks.

Designed for pipeline integration: pipe URLs via stdin or use --urls-file.

Examples:
  smuggled --url https://example.com
  smuggled --url https://example.com --json
  smuggled --urls-file targets.txt --workers 10 --output results.json
  cat targets.txt | smuggled
  smuggled https://example.com --skip-h2 --verbose`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if flagVersion {
			fmt.Printf("smuggled v%s\n", version)
			return nil
		}

		// Collect targets
		targets := collectTargets(args)
		if len(targets) == 0 {
			return fmt.Errorf("no target URLs provided — use --url, --urls-file, or pass URLs as arguments / stdin")
		}

		// Set up output writer
		var out *os.File
		if flagOutput != "" {
			f, err := os.Create(flagOutput)
			if err != nil {
				return fmt.Errorf("open output file: %w", err)
			}
			defer f.Close()
			out = f
		} else {
			out = os.Stdout
		}

		outFmt := report.FormatText
		if flagJSON {
			outFmt = report.FormatJSON
		}

		w := report.New(outFmt, out, flagVerbose)

		opts := scan.Options{
			Timeout:          time.Duration(flagTimeout) * time.Second,
			ConfirmRounds:    flagConfirmRounds,
			Workers:          flagWorkers,
			Verbose:          flagVerbose,
			ProxyURL:         flagProxy,
			SkipH2:           flagSkipH2,
			SkipParser:       flagSkipParser,
			SkipClientDesync: flagSkipClientDesync,
			SkipPause:        flagSkipPause,
			OnlyTechniques:   flagTechniques,
		}

		scanner := scan.New(opts)

		// Print JSON envelope opener
		if flagJSON && len(targets) > 1 {
			fmt.Fprintf(out, "[\n")
		}

		total := len(targets)
		foundCount := 0

		for i, target := range targets {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}

			if !flagJSON {
				w.PrintScanStart(target)
			}

			start := time.Now()
			findings, err := scanner.Scan(target)
			elapsed := time.Since(start)

			if err != nil {
				w.PrintError(target, err)
				continue
			}

			if len(findings) == 0 {
				w.PrintNoFindings(target)
			} else {
				foundCount += len(findings)
				w.PrintFindings(findings)
			}

			if !flagJSON {
				w.PrintScanComplete(target, findings, elapsed)
			}

			if flagJSON && len(targets) > 1 && i < total-1 {
				fmt.Fprintf(out, ",\n")
			}
		}

		if flagJSON && len(targets) > 1 {
			fmt.Fprintf(out, "]\n")
		}

		if !flagJSON {
			fmt.Fprintf(os.Stderr, "Done. %d finding(s) across %d target(s).\n", foundCount, total)
		}

		// Exit 1 if any findings (useful for CI/CD pipelines)
		if foundCount > 0 {
			os.Exit(1)
		}

		return nil
	},
}

func init() {
	RootCmd.Flags().StringVarP(&flagURL, "url", "u", "", "Single target URL to scan")
	RootCmd.Flags().StringVarP(&flagURLsFile, "urls-file", "f", "", "File with one URL per line")
	RootCmd.Flags().IntVarP(&flagTimeout, "timeout", "t", 15, "Network timeout in seconds per probe")
	RootCmd.Flags().IntVarP(&flagWorkers, "workers", "w", 5, "Concurrent workers for permutation testing")
	RootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose per-probe output")
	RootCmd.Flags().BoolVarP(&flagJSON, "json", "j", false, "Output findings as JSON")
	RootCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Write output to file (default: stdout)")
	RootCmd.Flags().StringVarP(&flagProxy, "proxy", "p", "", "HTTP CONNECT proxy URL (e.g. http://127.0.0.1:8080)")
	RootCmd.Flags().BoolVar(&flagSkipH2, "skip-h2", false, "Skip HTTP/2 downgrade checks")
	RootCmd.Flags().BoolVar(&flagSkipParser, "skip-parser", false, "Skip parser-discrepancy scan (v3.0)")
	RootCmd.Flags().BoolVar(&flagSkipClientDesync, "skip-client-desync", false, "Skip client-side desync detection")
	RootCmd.Flags().BoolVar(&flagSkipPause, "skip-pause", false, "Skip pause-based desync detection")
	RootCmd.Flags().IntVar(&flagConfirmRounds, "confirm", 3, "Number of confirmation probes required before reporting")
	RootCmd.Flags().StringSliceVar(&flagTechniques, "techniques", nil, "Comma-separated list of technique names to test (default: all)")
	RootCmd.Flags().BoolVar(&flagVersion, "version", false, "Print version and exit")
}

// collectTargets aggregates URLs from: positional args, --url, --urls-file, stdin.
func collectTargets(args []string) []string {
	var targets []string

	// Positional args
	targets = append(targets, args...)

	// --url flag
	if flagURL != "" {
		targets = append(targets, flagURL)
	}

	// --urls-file
	if flagURLsFile != "" {
		lines, err := readLines(flagURLsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", flagURLsFile, err)
		} else {
			targets = append(targets, lines...)
		}
	}

	// stdin (when piped — not a TTY)
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}

	// Deduplicate
	seen := make(map[string]struct{})
	unique := targets[:0]
	for _, t := range targets {
		if _, ok := seen[t]; !ok {
			seen[t] = struct{}{}
			unique = append(unique, t)
		}
	}
	return unique
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
