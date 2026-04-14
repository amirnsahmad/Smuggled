// Package cmd implements the Smuggled CLI using cobra.
package cmd

import (
	"bufio"
	"fmt"
	"io"
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
	flagDebug        int
	flagJSON         bool
	flagOutput       string
	flagProxy        string
	flagSkipTLS      bool
	flagConfirm      int
	flagMethods      []string
	flagForceMethod  bool
	flagAll          bool // master switch: enable everything including research
	flagHTTP1        bool // restrict to HTTP/1.1 scanners
	flagHTTP2        bool // restrict to HTTP/2 scanners

	flagSkipCLTE          bool
	flagSkipTECL          bool
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
	flagSkipPathCRLF      bool
	flagResearch          bool
	flagExitOnFind        bool
	flagCalibrate         bool
	flagTechniques        []string
	flagCanaryPath        string
	flagModules           []string
	flagHeaders           []string
	flagAttempts          int

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
	scanCmd.Flags().IntVar(&flagDebug, "debug", 0,
		"Debug level: 1 = probe summary (first line + status/elapsed),\n"+
			"  2 = full raw dump of every request and response sent/received.\n"+
			"  Usage: --debug 1  or  --debug 2")
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

	scanCmd.Flags().BoolVar(&flagSkipCLTE, "skip-clte", false, "Skip CL.TE desync scans")
	scanCmd.Flags().BoolVar(&flagSkipTECL, "skip-tecl", false, "Skip TE.CL desync scans")
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
	scanCmd.Flags().BoolVar(&flagSkipPathCRLF, "skip-path-crlf", false, "Skip path CRLF injection scans (H1 and H2)")
	scanCmd.Flags().BoolVar(&flagResearch, "research", false, "Enable research-mode H2 probes (HTTP2FakePseudo, HTTP2Scheme, HTTP2DualPath, HTTP2Method, HiddenHTTP2)")
	scanCmd.Flags().BoolVarP(&flagExitOnFind, "exit", "x", false,
		"After the first finding in a module, skip remaining techniques in that module\n"+
			"  and move on to the next module. All modules still run.\n"+
			"  Default (without -x): test ALL techniques in ALL modules regardless of findings.")
	scanCmd.Flags().BoolVarP(&flagCalibrate, "calibrate", "C", false,
		"Auto-calibrate timing: send baseline requests to measure normal\n"+
			"  response time, then detect delayed responses (not just hard timeouts).\n"+
			"  Threshold = median baseline + 3s floor. Applies to ALL timing modules.")
	scanCmd.Flags().BoolVar(&flagHTTP1, "http1", false,
		"Scan HTTP/1.1 vulnerabilities only (CL.TE, TE.CL, CL.0, parser-discrepancy, etc.).\n"+
			"  If the target does not respond to HTTP/1.1, these scans are skipped automatically.")
	scanCmd.Flags().BoolVar(&flagHTTP2, "http2", false,
		"Scan HTTP/2 vulnerabilities only (H2.TE, H2.CL, H2-tunnel, H2-research, etc.).\n"+
			"  If the target does not negotiate HTTP/2 via ALPN, these scans are skipped automatically.\n"+
			"  Default (neither --http1 nor --http2): both protocol scan sets are run.")
	scanCmd.Flags().BoolVarP(&flagAll, "all", "a", false,
		"Enable ALL modules including research probes.\n"+
			"  Equivalent to: --research + all --skip-* disabled + -m POST,GET,HEAD\n"+
			"  Individual flags can still override: --all --skip-h2 disables H2 on top of --all.")
	scanCmd.Flags().StringSliceVar(&flagTechniques, "techniques", nil, "Comma-separated technique names to run (default: all). See 'techniques' subcommand.")
	scanCmd.Flags().StringSliceVar(&flagModules, "modules", nil,
		"Comma-separated module names to run (default: all). When set, --skip-* flags are ignored.\n"+
			"  Modules: clte, tecl, cl0, chunksizes, parser, client-desync, conn-state,\n"+
			"  pause, implicit-zero, h1-tunnel, header-removal, h2, h2-tunnel, h2-research.")
	scanCmd.Flags().StringArrayVarP(&flagHeaders, "header", "H", nil,
		"Add a custom header to all requests (repeatable). Format: \"Name: Value\".\n"+
			"  Examples: -H \"Authorization: Bearer token\" -H \"Cookie: session=abc\".\n"+
			"  Cookie headers are merged with auto-captured session cookies.")
	scanCmd.Flags().IntVar(&flagAttempts, "attempts", 5,
		"Number of attack+probe cycles for pipeline-poisoning modules (CL.0, H2.CL0,\n"+
			"  H2.CL smuggle, H2.CL inject). Higher values improve detection on targets\n"+
			"  with large connection pools but send more requests. Default: 5.")
	scanCmd.Flags().StringVar(&flagCanaryPath, "canary-path", "",
		"URL path for smuggled canary requests (default: "+config.DefaultCanaryPath+").\n"+
			"  Used by H2.CL, CL.0, and other poison-detection probes.\n"+
			"  Useful when WAF or routing filters the default path.")

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

	// findingsOut receives Emit output only (the file when -o is set, stdout otherwise).
	// progress always goes to stdout so operator feedback never pollutes the findings file.
	findingsOut := io.Writer(os.Stdout)
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("opening output file: %w", err)
		}
		defer f.Close()
		findingsOut = f
	}

	rep := report.New(findingsOut, os.Stdout, flagJSON, flagVerbose)

	// --all: enable every module and method set; individual --skip-* flags
	// applied afterwards can still narrow the scope.
	methods          := flagMethods
	skipCLTE         := flagSkipCLTE
	skipTECL         := flagSkipTECL
	skipH2           := flagSkipH2
	skipParser       := flagSkipParser
	skipClientDesync := flagSkipClientDesync
	skipPause        := flagSkipPause
	skipImplicit     := flagSkipImplicit
	skipConnState    := flagSkipConnState
	skipCL0          := flagSkipCL0
	skipChunkSizes   := flagSkipChunkSizes
	skipH1Tunnel     := flagSkipH1Tunnel
	skipH2Tunnel     := flagSkipH2Tunnel
	skipHeaderRemoval := flagSkipHeaderRemoval
	skipPathCRLF     := flagSkipPathCRLF
	researchMode     := flagResearch

	if flagAll {
		if len(methods) == 0 {
			methods = []string{"POST", "GET", "HEAD"}
		}
		researchMode = true
		_ = skipCLTE
		_ = skipTECL
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
		_ = skipPathCRLF
	}

	// Debug logging callback — prints to stderr so it doesn't interfere with JSON output
	var debugLog func(string, ...any)
	if flagDebug >= 1 {
		debugLog = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
		}
	}

	cfg := config.Config{
		Timeout:           time.Duration(flagTimeout) * time.Second,
		Proxy:             flagProxy,
		SkipTLSVerify:     flagSkipTLS,
		Verbose:           flagVerbose,
		Debug:             flagDebug,
		DebugLog:          debugLog,
		Workers:           flagWorkers,
		ConfirmReps:       flagConfirm,
		Methods:           methods,
		ForceMethod:       flagForceMethod,
		ScanHTTP1:         flagHTTP1,
		ScanHTTP2:         flagHTTP2,
		SkipCLTE:          skipCLTE,
		SkipTECL:          skipTECL,
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
		SkipPathCRLF:      skipPathCRLF,
		ExtraHeaders:      flagHeaders,
		Modules:           flagModules,
		ResearchMode:      researchMode,
		ExitOnFind:        flagExitOnFind,
		Calibrate:         flagCalibrate,
		CalibrationFloor:  config.DefaultCalibrationFloor,
		TechniquesFilter:  flagTechniques,
		CanaryPath:        flagCanaryPath,
		Attempts:          flagAttempts,
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
