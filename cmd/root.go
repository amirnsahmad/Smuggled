// Package cmd implements the Smuggled CLI using cobra.
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/smuggled/smuggled/pkg/permute"
	"github.com/smuggled/smuggled/pkg/report"
	"github.com/smuggled/smuggled/pkg/scan"
)

var (
	flagURL          string
	flagURLsFile     string
	flagTimeout      int
	flagWorkers      int
	flagVerbose      bool
	flagJSON         bool
	flagOutput       string
	flagProxy        string
	flagSkipTLS      bool
	flagConfirm      int

	flagSkipH2          bool
	flagSkipParser      bool
	flagSkipClientDesync bool
	flagSkipPause       bool
	flagSkipImplicit    bool
	flagSkipConnState   bool
	flagTechniques      []string

	rootCmd = &cobra.Command{
		Use:   "smuggled",
		Short: "HTTP Request Smuggling detection CLI",
		Long: `Smuggled — HTTP Request Smuggling Scanner
Detects CL.TE, TE.CL, H2.TE, H2.CL, parser discrepancy, client-side desync,
connection-state, implicit-zero and pause-based desync vulnerabilities.

For authorized pentesting and security research only.`,
	}

	scanCmd = &cobra.Command{
		Use:   "scan [url...]",
		Short: "Scan one or more URLs for HTTP request smuggling",
		Long: `Scan URLs for all known HTTP request smuggling variants.

Examples:
  smuggled scan https://example.com
  smuggled scan -u https://example.com --verbose
  smuggled scan -f targets.txt --workers 10 --json
  cat urls.txt | smuggled scan
  smuggled scan https://a.com https://b.com --skip-h2 --timeout 15`,
		RunE: runScan,
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version info",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("smuggled v1.0.0")
			fmt.Println("Based on PortSwigger http-request-smuggler (James Kettle)")
			fmt.Println("Rewritten in Go for standalone pipeline use")
		},
	}

	listTechCmd = &cobra.Command{
		Use:   "techniques",
		Short: "List all available permutation techniques",
		Run:   runListTechniques,
	}
)

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	scanCmd.Flags().StringVarP(&flagURL, "url", "u", "", "Single target URL")
	scanCmd.Flags().StringVarP(&flagURLsFile, "urls-file", "f", "", "File with one URL per line")
	scanCmd.Flags().IntVarP(&flagTimeout, "timeout", "t", 10, "Request timeout in seconds")
	scanCmd.Flags().IntVarP(&flagWorkers, "workers", "w", 5, "Number of concurrent workers")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose output")
	scanCmd.Flags().BoolVarP(&flagJSON, "json", "j", false, "JSON output (one finding per line, good for pipelines)")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Write output to file")
	scanCmd.Flags().StringVarP(&flagProxy, "proxy", "p", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080)")
	scanCmd.Flags().BoolVar(&flagSkipTLS, "skip-tls-verify", false, "Skip TLS certificate verification")
	scanCmd.Flags().IntVarP(&flagConfirm, "confirm", "c", 3, "Confirmations required to reduce false positives")

	scanCmd.Flags().BoolVar(&flagSkipH2, "skip-h2", false, "Skip HTTP/2 downgrade scans")
	scanCmd.Flags().BoolVar(&flagSkipParser, "skip-parser", false, "Skip parser discrepancy scans")
	scanCmd.Flags().BoolVar(&flagSkipClientDesync, "skip-client-desync", false, "Skip client-side desync scans")
	scanCmd.Flags().BoolVar(&flagSkipPause, "skip-pause", false, "Skip pause-based desync scans")
	scanCmd.Flags().BoolVar(&flagSkipImplicit, "skip-implicit", false, "Skip implicit zero CL scans")
	scanCmd.Flags().BoolVar(&flagSkipConnState, "skip-conn-state", false, "Skip connection state manipulation scans")
	scanCmd.Flags().StringSliceVar(&flagTechniques, "techniques", nil, "Comma-separated technique names to run (default: all)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(listTechCmd)
}

func runScan(_ *cobra.Command, args []string) error {
	var targets []string

	if flagURL != "" {
		targets = append(targets, flagURL)
	}
	targets = append(targets, args...)

	if flagURLsFile != "" {
		lines, err := readLines(flagURLsFile)
		if err != nil {
			return fmt.Errorf("reading urls-file: %w", err)
		}
		targets = append(targets, lines...)
	}

	// stdin pipe support
	if len(targets) == 0 {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			lines, err := readLines("")
			if err != nil {
				return err
			}
			targets = append(targets, lines...)
		}
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets — use -u, -f, positional args, or pipe URLs via stdin")
	}

	out := os.Stdout
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("opening output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	rep := report.New(out, flagJSON, flagVerbose)

	cfg := scan.Config{
		Timeout:             time.Duration(flagTimeout) * time.Second,
		Proxy:               flagProxy,
		SkipTLSVerify:       flagSkipTLS,
		Verbose:             flagVerbose,
		Workers:             flagWorkers,
		ConfirmReps:         flagConfirm,
		SkipH2:              flagSkipH2,
		SkipParser:          flagSkipParser,
		SkipClientDesync:    flagSkipClientDesync,
		SkipPause:           flagSkipPause,
		SkipImplicitZero:    flagSkipImplicit,
		SkipConnectionState: flagSkipConnState,
		TechniquesFilter:    flagTechniques,
	}

	ch := make(chan string, len(targets))
	for _, t := range targets {
		ch <- t
	}
	close(ch)

	workers := flagWorkers
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := scan.New(cfg, rep)
			for target := range ch {
				s.Scan(target)
			}
		}()
	}
	wg.Wait()

	if !flagJSON {
		rep.Progress("scan complete — %d target(s) processed", len(targets))
	}
	return nil
}

func runListTechniques(_ *cobra.Command, _ []string) {
	all := permute.All()
	fmt.Printf("%-45s %-8s %s\n", "TECHNIQUE", "H2-ONLY", "DESCRIPTION")
	fmt.Printf("%s\n", repeatStr("-", 100))
	for _, t := range all {
		h2 := ""
		if t.H2Only {
			h2 = "yes"
		}
		fmt.Printf("%-45s %-8s %s\n", t.Name, h2, t.Description)
	}
	fmt.Printf("\nTotal: %d techniques\n", len(all))
}

func readLines(path string) ([]string, error) {
	var scanner *bufio.Scanner
	if path == "" {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	}
	var lines []string
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func repeatStr(s string, n int) string {
	result := make([]byte, n*len(s))
	for i := range result {
		result[i] = s[i%len(s)]
	}
	return string(result)
}
