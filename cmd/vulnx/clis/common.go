package clis

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"time"

	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	_ "embed"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/gologger"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"

	"github.com/mark3labs/mcp-go/server"
	"github.com/projectdiscovery/cvemap/pkg/tools"
	"github.com/projectdiscovery/cvemap/pkg/tools/id"
	"github.com/projectdiscovery/cvemap/pkg/tools/renderer"
	fileutil "github.com/projectdiscovery/utils/file"
)

//go:embed banner.txt
var vulnxBanner string

var (
	verbose bool
	debug   bool

	// HTTP client config
	httpProxy   string
	httpTimeout time.Duration

	// Global cvemap client
	cvemapClient *cvemap.Client

	debugReq  bool
	debugResp bool

	// Add global json and output flags
	jsonOutput bool
	outputFile string

	// Add global silent flag
	silent bool

	// Add global no-color flag
	noColor bool

	// Track if the banner has already been shown for this invocation
	bannerShown bool

	// CVE ID regex pattern
	cveIDRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

	rootCmd = &cobra.Command{
		Use:   "vulnx",
		Short: "vulnx — The Swiss Army knife for vulnerability intel",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Do not print the banner when running the "mcp" sub-command as it
			// can interfere with clients expecting clean JSON output.
			if cmd.Name() != "mcp" && !silent {
				showBanner()
			}
			return ensureCvemapClientInitialized(cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no subcommand is provided and stdin has data, try to auto-detect the command
			if len(args) == 0 && fileutil.HasStdin() {
				return handleStdinAutoDetection(cmd, args)
			}
			// Otherwise, show help
			return cmd.Help()
		},
	}

	mcpCmd = &cobra.Command{
		Use:   "mcp",
		Short: "Start MCP server for vulnx (ProjectDiscovery vulnerability.sh) tools",
		Run: func(cmd *cobra.Command, args []string) {
			mode, _ := cmd.Flags().GetString("mode")
			port, _ := cmd.Flags().GetInt("port")
			if debug {
				fmt.Fprintln(os.Stderr, "\nProjectDiscovery vulnerability.sh (vulnx) MCP server mode\n----------------------------------------------")
			}
			s := server.NewMCPServer(
				"ProjectDiscovery vulnerability.sh (vulnx)",
				"1.0.0",
				server.WithToolCapabilities(false),
				server.WithRecovery(),
			)
			for _, tool := range tools.AllMCPTools(cvemapClient) {
				s.AddTool(tool.MCPToolSpec(), tool.MCPHandler(cvemapClient))
			}
			switch mode {
			case "stdio":
				if err := server.ServeStdio(s); err != nil {
					fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
				}
			case "sse":
				addr := fmt.Sprintf(":%d", port)
				if debug {
					fmt.Fprintf(os.Stderr, "Starting MCP SSE server on %s...\n", addr)
				}
				// TODO: Integrate proper SSE handler from MCP server package when available
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotImplemented)
					if _, err := w.Write([]byte("SSE mode is not yet implemented in this build. Please update the MCP server package or implement SSE handler.")); err != nil {
						gologger.Error().Msgf("Failed to write SSE not implemented message: %s", err)
					}
				})
				if err := http.ListenAndServe(addr, handler); err != nil {
					fmt.Fprintf(os.Stderr, "SSE server error: %v\n", err)
				}
			case "http":
				fmt.Fprintln(os.Stderr, "HTTP mode is not supported in this build. Use --mode stdio or --mode sse.")
				os.Exit(1)
			default:
				fmt.Fprintf(os.Stderr, "Unknown mode: %s\n", mode)
			}
		},
	}
)

func init() {
	// Global flags for gologger
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug output")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// HTTP client config flags
	rootCmd.PersistentFlags().StringVar(&httpProxy, "proxy", "", "HTTP proxy to use (e.g. http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().DurationVar(&httpTimeout, "timeout", 30*time.Second, "HTTP request timeout (e.g. 30s, 1m)")

	rootCmd.PersistentFlags().BoolVar(&debugReq, "debug-req", false, "Dump HTTP requests to stdout")
	rootCmd.PersistentFlags().BoolVar(&debugResp, "debug-resp", false, "Dump HTTP responses to stdout")

	// Add persistent json and output flags
	rootCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "Output raw JSON (for piping, disables YAML output)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Write output to file in JSON format (error if file exists)")

	// Add persistent silent flag
	rootCmd.PersistentFlags().BoolVar(&silent, "silent", false, "Silent mode (suppress banner and non-essential output)")

	// Add persistent no-color flag
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	// Custom help and usage to always show banner
	defaultHelpFunc := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !silent {
			showBanner()
		}
		defaultHelpFunc(cmd, args)
	})
	defaultUsageFunc := rootCmd.UsageFunc()
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		if !silent {
			showBanner()
		}
		return defaultUsageFunc(cmd)
	})

	mcpCmd.Flags().String("mode", "stdio", "MCP server mode: stdio or sse")
	mcpCmd.Flags().Int("port", 8080, "Port to listen on for SSE mode (default 8080)")
	rootCmd.AddCommand(mcpCmd)
}

// Execute executes the root command
func Execute() error {
	// Reset bannerShown for each top-level execution
	bannerShown = false
	return rootCmd.Execute()
}

// ensureCvemapClientInitialized initializes the global cvemapClient if it is nil.
func ensureCvemapClientInitialized(_ *cobra.Command) error {
	if cvemapClient == nil {
		if debug {
			debugReq = true
			debugResp = true
		}

		transport := &http.Transport{}
		if httpProxy != "" {
			proxyURL, err := url.Parse(httpProxy)
			if err != nil {
				return fmt.Errorf("invalid proxy URL: %w", err)
			}
			transport.Proxy = http.ProxyURL(proxyURL)
		} else {
			transport.Proxy = http.ProxyFromEnvironment
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   httpTimeout,
		}
		retryOpts := retryablehttp.DefaultOptionsSingle
		retryOpts.HttpClient = httpClient
		retryOpts.Verbose = debug

		var opts []cvemap.Option
		opts = append(opts, cvemap.WithKeyFromEnv(), cvemap.WithRetryableHTTPOptions(retryOpts))
		if debugReq {
			opts = append(opts, cvemap.WithDebugRequest(func(req *http.Request) {
				dump, err := httputil.DumpRequestOut(req, true)
				if err == nil {
					var sb strings.Builder
					sb.WriteString("--- HTTP REQUEST ---\n")
					sb.Write(dump)
					sb.WriteString("--------------------\n")
					gologger.Debug().MsgFunc(sb.String)
				}
			}))
		}
		if debugResp {
			opts = append(opts, cvemap.WithDebugResponse(func(resp *http.Response) {
				dump, err := httputil.DumpResponse(resp, true)
				if err == nil {
					var sb strings.Builder
					sb.WriteString("--- HTTP RESPONSE ---\n")
					sb.Write(dump)
					sb.WriteString("---------------------\n")
					gologger.Debug().MsgFunc(sb.String)
				}
			}))
		}
		client, err := cvemap.New(opts...)
		if err != nil {
			return fmt.Errorf("failed to initialize cvemap client: %w", err)
		}
		cvemapClient = client
	}
	return nil
}

func showBanner() {
	if bannerShown || silent {
		return
	}
	gologger.Print().Msgf("%s\n", vulnxBanner)
	bannerShown = true
}

func handleStdinAutoDetection(cmd *cobra.Command, args []string) error {
	// Read stdin content
	stdinData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	content := strings.TrimSpace(string(stdinData))
	if content == "" {
		return fmt.Errorf("no input provided via stdin")
	}

	// Check if the content looks like CVE IDs
	if isCVEContent(content) {
		// Auto-route to id command
		return executeIDCommand(content)
	}

	// If not CVE IDs, show help
	return cmd.Help()
}

func isCVEContent(content string) bool {
	// Check if content contains CVE IDs
	lines := strings.Split(content, "\n")
	cveCount := 0
	totalLines := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		totalLines++

		// Check if line contains CVE IDs (either directly or comma-separated)
		if cveIDRegex.MatchString(line) {
			cveCount++
		}
	}

	// Consider it CVE content if majority of non-empty lines contain CVE IDs
	return totalLines > 0 && cveCount > 0 && float64(cveCount)/float64(totalLines) >= 0.5
}

func executeIDCommand(content string) error {
	// Parse CVE IDs from content
	var cveIDs []string

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle comma-separated values on a single line
		if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if cveIDRegex.MatchString(part) {
					cveIDs = append(cveIDs, part)
				}
			}
		} else {
			// Single CVE ID per line
			matches := cveIDRegex.FindAllString(line, -1)
			cveIDs = append(cveIDs, matches...)
		}
	}

	if len(cveIDs) == 0 {
		return fmt.Errorf("no valid CVE IDs found in stdin input")
	}

	// Remove duplicates
	cveIDs = removeDuplicateStrings(cveIDs)

	// Execute id command with the parsed CVE IDs
	return executeIDWithIDs(cveIDs)
}

func removeDuplicateStrings(ids []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}

	return result
}

func executeIDWithIDs(cveIDs []string) error {
	// Call the id command logic directly
	return runIDCommandWithIDs(cveIDs)
}

func runIDCommandWithIDs(cveIDs []string) error {
	// Limit to 100 IDs for performance
	if len(cveIDs) > 100 {
		gologger.Warning().Msgf("Processing %d IDs. Limiting to first 100 for performance.", len(cveIDs))
		cveIDs = cveIDs[:100]
	}

	// Use the global cvemapClient
	handler := id.NewHandler(cvemapClient)

	// Handle JSON output for multiple IDs
	if jsonOutput || outputFile != "" {
		var allVulns []*cvemap.Vulnerability
		for _, vulnID := range cveIDs {
			vuln, err := handler.Get(vulnID)
			if err != nil {
				if err.Error() == "not found" {
					gologger.Warning().Msgf("Vulnerability not found: %s", vulnID)
					continue
				}
				gologger.Error().Msgf("Failed to fetch vulnerability %s: %s", vulnID, err)
				continue
			}
			allVulns = append(allVulns, vuln)
		}

		if len(allVulns) == 0 {
			gologger.Fatal().Msg("No vulnerabilities were successfully retrieved")
		}

		// Marshal single item or array based on input
		var jsonBytes []byte
		var err error
		if len(cveIDs) == 1 && len(allVulns) == 1 {
			jsonBytes, err = json.MarshalIndent(allVulns[0], "", "  ")
		} else {
			jsonBytes, err = json.MarshalIndent(allVulns, "", "  ")
		}

		if err != nil {
			gologger.Fatal().Msgf("Failed to marshal JSON: %s", err)
		}

		if outputFile != "" {
			// Check if file exists
			if _, err := os.Stat(outputFile); err == nil {
				gologger.Fatal().Msgf("Output file already exists: %s", outputFile)
			}
			f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if err != nil {
				gologger.Fatal().Msgf("Failed to create output file: %s", err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					gologger.Error().Msgf("Failed to close output file: %s", err)
				}
			}()
			if _, err := f.Write(jsonBytes); err != nil {
				gologger.Fatal().Msgf("Failed to write to output file: %s", err)
			}
			gologger.Info().Msgf("Wrote %d vulnerability(s) to file: %s", len(allVulns), outputFile)
			return nil
		}

		// Print to stdout
		if _, err := os.Stdout.Write(jsonBytes); err != nil {
			gologger.Error().Msgf("Failed to write JSON to stdout: %s", err)
		}
		if _, err := os.Stdout.Write([]byte("\n")); err != nil {
			gologger.Error().Msgf("Failed to write newline to stdout: %s", err)
		}
		return nil
	}

	// CLI output for multiple vulnerabilities
	// Determine color configuration
	var colors *renderer.ColorConfig
	if noColor || !renderer.IsTerminal() {
		colors = renderer.NoColorConfig()
	} else {
		colors = renderer.DefaultColorConfig()
	}

	successCount := 0
	for i, vulnID := range cveIDs {
		vuln, err := handler.Get(vulnID)
		if err != nil {
			if err.Error() == "not found" {
				gologger.Warning().Msgf("Vulnerability not found: %s", vulnID)
				continue
			}
			gologger.Error().Msgf("Failed to fetch vulnerability %s: %s", vulnID, err)
			continue
		}

		// Convert to renderer entry
		entry := renderer.FromVulnerability(vuln)
		if entry == nil {
			gologger.Error().Msgf("Failed to convert vulnerability data for %s", vulnID)
			continue
		}

		// Add separator between multiple results
		if i > 0 && successCount > 0 {
			separator := strings.Repeat("─", 65)
			if colors != nil {
				fmt.Println(colors.ColorResultSeparator(separator))
			} else {
				fmt.Println(separator)
			}
			fmt.Println()
		}

		// Render detailed output
		result := renderer.RenderDetailed(entry, colors)
		fmt.Println(result)
		successCount++
	}

	if successCount == 0 {
		gologger.Fatal().Msg("No vulnerabilities were successfully retrieved")
	} else if successCount < len(cveIDs) {
		gologger.Info().Msgf("Successfully retrieved %d out of %d vulnerabilities", successCount, len(cveIDs))
	}

	return nil
}
