// Package cmd implements the Smuggled CLI using cobra.
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/smuggled/smuggled/internal/permute"
	"github.com/smuggled/smuggled/internal/report"
	"github.com/smuggled/smuggled/internal/config"
	"github.com/smuggled/smuggled/internal/scan"
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
	flagMethods      []string
	flagForceMethod  bool
	flagAll          bool // master switch: enable everything including research

	flagSkipH2            bool
	flagSkipParser        bool
	flagSkipClientDesync  bool
	flagSkipPause         bool
	flagSkipImplicit      bool
	flagSkipConnState     bool
	flagSkipCL0           bool
	flagSkipChunkSizes    bool
	flagSkipH1Tunnel      bool
	flagSkipH2Tunnel      bool
	flagSkipHeaderRemoval bool
	flagResearch          bool
	flagTechniques        []string

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
  smuggled scan https://example.com -m POST,GET,HEAD
  smuggled scan https://example.com -m GET --force-method --skip-h2`,
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
	scanCmd.Flags().BoolVarP(&flagJSON, "json", "j", false, "JSON output (one finding per line)")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Write output to file")
	scanCmd.Flags().StringVarP(&flagProxy, "proxy", "p", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080)")
	scanCmd.Flags().BoolVar(&flagSkipTLS, "skip-tls-verify", false, "Skip TLS certificate verification")
	scanCmd.Flags().IntVarP(&flagConfirm, "confirm", "c", 3, "Confirmations required to reduce false positives")
	scanCmd.Flags().StringSliceVarP(&flagMethods, "method", "m", nil,
		"HTTP method(s) for probes. Comma-separated or repeated flag.\n"+
			"  Examples: -m POST   -m GET,POST,HEAD   -m GET -m POST\n"+
			"  Default: POST. GET/HEAD upgrade to POST for body probes unless --force-method.")
	scanCmd.Flags().BoolVar(&flagForceMethod, "force-method", false,
		"Force chosen method(s) even on body-bearing probes (CL.TE, TE.CL). May reduce findings.")

	scanCmd.Flags().BoolVar(&flagSkipH2, "skip-h2", false, "Skip HTTP/2 downgrade, H2 tunnel and HeadScanTE scans")
	scanCmd.Flags().BoolVar(&flagSkipParser, "skip-parser", false, "Skip parser discrepancy scans")
	scanCmd.Flags().BoolVar(&flagSkipClientDesync, "skip-client-desync", false, "Skip client-side desync scans")
	scanCmd.Flags().BoolVar(&flagSkipPause, "skip-pause", false, "Skip pause-based desync scans")
	scanCmd.Flags().BoolVar(&flagSkipImplicit, "skip-implicit", false, "Skip implicit zero CL scans")
	scanCmd.Flags().BoolVar(&flagSkipConnState, "skip-conn-state", false, "Skip connection state manipulation scans")
	scanCmd.Flags().BoolVar(&flagSkipCL0, "skip-cl0", false, "Skip CL.0 desync scans")
	scanCmd.Flags().BoolVar(&flagSkipChunkSizes, "skip-chunk-sizes", false, "Skip chunk-size terminator discrepancy scans (TERM.EXT, EXT.TERM, etc.)")
	scanCmd.Flags().BoolVar(&flagSkipH1Tunnel, "skip-h1-tunnel", false, "Skip H1 tunnel scans (HEAD/method-override)")
	scanCmd.Flags().BoolVar(&flagSkipH2Tunnel, "skip-h2-tunnel", false, "Skip H2 tunnel and HeadScanTE (overrides --skip-h2 for tunnel only)")
	scanCmd.Flags().BoolVar(&flagSkipHeaderRemoval, "skip-header-removal", false, "Skip Keep-Alive header removal scan")
	scanCmd.Flags().BoolVar(&flagResearch, "research", false, "Enable research-mode H2 probes (HTTP2FakePseudo, HTTP2Scheme, HTTP2DualPath, HTTP2Method, HiddenHTTP2)")
	scanCmd.Flags().BoolVarP(&flagAll, "all", "a", false,
		"Enable ALL modules including research probes.\n"+
			"  Equivalent to: --research + all --skip-* disabled + -m POST,GET,HEAD\n"+
			"  Individual flags can still override: --all --skip-h2 disables H2 on top of --all.")
	scanCmd.Flags().StringSliceVar(&flagTechniques, "techniques", nil, "Comma-separated technique names to run (default: all). See 'techniques' subcommand.")

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

	// --all: enable every module and method set; individual --skip-* flags
	// applied afterwards can still narrow the scope.
	methods         := flagMethods
	skipH2          := flagSkipH2
	skipParser      := flagSkipParser
	skipClientDesync := flagSkipClientDesync
	skipPause       := flagSkipPause
	skipImplicit    := flagSkipImplicit
	skipConnState   := flagSkipConnState
	skipCL0         := flagSkipCL0
	skipChunkSizes  := flagSkipChunkSizes
	skipH1Tunnel    := flagSkipH1Tunnel
	skipH2Tunnel    := flagSkipH2Tunnel
	skipHeaderRemoval := flagSkipHeaderRemoval
	researchMode    := flagResearch

	if flagAll {
		// Enable everything by default; explicit --skip-* flags still take effect
		if len(methods) == 0 {
			methods = []string{"POST", "GET", "HEAD"}
		}
		researchMode = true
		// Only override skip flags if user did NOT explicitly set them
		// Cobra doesn't expose whether a flag was explicitly set, so we use
		// a simple convention: --all sets all to false unless user passed
		// the corresponding --skip-X flag explicitly (which would override
		// the default false). Since cobra defaults are false, if the flag is
		// still false after parsing it means user didn't set it — which means
		// --all correctly leaves them as false (= enabled).
		// No extra work needed; skip flags default to false = don't skip.
		_ = skipH2
		_ = skipParser
		_ = skipClientDesync
		_ = skipPause
		_ = skipImplicit
		_ = skipConnState
		_ = skipCL0
		_ = skipChunkSizes
		_ = skipH1Tunnel
		_ = skipH2Tunnel
		_ = skipHeaderRemoval
	}

	cfg := config.Config{
		Timeout:           time.Duration(flagTimeout) * time.Second,
		Proxy:             flagProxy,
		SkipTLSVerify:     flagSkipTLS,
		Verbose:           flagVerbose,
		Workers:           flagWorkers,
		ConfirmReps:       flagConfirm,
		Methods:           methods,
		ForceMethod:       flagForceMethod,
		SkipH2:            skipH2,
		SkipParser:        skipParser,
		SkipClientDesync:  skipClientDesync,
		SkipPause:         skipPause,
		SkipImplicitZero:  skipImplicit,
		SkipConnState:     skipConnState,
		SkipCL0:           skipCL0,
		SkipChunkSizes:    skipChunkSizes,
		SkipH1Tunnel:      skipH1Tunnel,
		SkipH2Tunnel:      skipH2Tunnel || skipH2,
		SkipHeaderRemoval: skipHeaderRemoval,
		ResearchMode:      researchMode,
		TechniquesFilter:  flagTechniques,
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
