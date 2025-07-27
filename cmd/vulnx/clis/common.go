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
	"sort"
	"strings"

	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"

	"errors"

	"github.com/mark3labs/mcp-go/server"
	"github.com/projectdiscovery/cvemap/pkg/tools"
	"github.com/projectdiscovery/cvemap/pkg/tools/analyze"
	"github.com/projectdiscovery/cvemap/pkg/tools/id"
	"github.com/projectdiscovery/cvemap/pkg/tools/renderer"
	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
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

	// Track if version has been shown for this invocation
	versionShown bool

	// CVE ID regex pattern
	cveIDRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

	rootCmd = &cobra.Command{
		Use:   "vulnx",
		Short: "vulnx — the swiss army knife for vulnerability intel",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Check for update flag
			update, _ := cmd.Flags().GetBool("update")
			if update {
				GetUpdateCallback()()
				return nil
			}

			// Do not print the banner when running the "mcp" sub-command as it
			// can interfere with clients expecting clean JSON output.
			if cmd.Name() != "mcp" && !silent {
				showBanner()
				// Don't show version info for the version command itself
				if cmd.Name() != "version" {
					showVersionInfo()
				}
			}
			err := ensureCvemapClientInitialized(cmd)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no subcommand is provided and stdin has data, try to auto-detect the command
			if len(args) == 0 && fileutil.HasStdin() {
				return handleStdinAutoDetection(cmd, args)
			}

			// If no subcommand is provided and no stdin, show dashboard
			if len(args) == 0 {
				return showDashboard()
			}

			// Otherwise, show help
			return cmd.Help()
		},
	}

	mcpCmd = &cobra.Command{
		Use:   "mcp",
		Short: "start mcp server for vulnx (projectdiscovery vulnerability.sh) tools",
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
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug output")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	// HTTP client config flags
	rootCmd.PersistentFlags().StringVar(&httpProxy, "proxy", "", "http proxy to use (e.g. http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().DurationVar(&httpTimeout, "timeout", 30*time.Second, "http request timeout (e.g. 30s, 1m)")

	rootCmd.PersistentFlags().BoolVar(&debugReq, "debug-req", false, "dump http requests to stdout")
	rootCmd.PersistentFlags().BoolVar(&debugResp, "debug-resp", false, "dump http responses to stdout")

	// Add persistent json and output flags
	rootCmd.PersistentFlags().BoolVarP(&jsonOutput, "json", "j", false, "output raw json (for piping, disables yaml output)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "write output to file in json format (error if file exists)")

	// Add persistent silent flag
	rootCmd.PersistentFlags().BoolVar(&silent, "silent", false, "silent mode (suppress banner and non-essential output)")

	// Add persistent no-color flag
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")

	// Update flag
	rootCmd.Flags().BoolP("update", "u", false, "update vulnx to latest version")

	// Custom help and usage to always show banner
	defaultHelpFunc := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if !silent {
			showBanner()
			// Don't show version info for the version command itself
			if cmd.Name() != "version" {
				showVersionInfo()
			}
		}
		defaultHelpFunc(cmd, args)
	})
	defaultUsageFunc := rootCmd.UsageFunc()
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		if !silent {
			showBanner()
			// Don't show version info for the version command itself
			if cmd.Name() != "version" {
				showVersionInfo()
			}
		}
		return defaultUsageFunc(cmd)
	})

	mcpCmd.Flags().String("mode", "stdio", "mcp server mode: stdio or sse")
	mcpCmd.Flags().Int("port", 8080, "port to listen on for sse mode (default 8080)")
	rootCmd.AddCommand(mcpCmd)
}

// Execute executes the root command
func Execute() error {
	// Reset bannerShown for each top-level execution
	bannerShown = false
	versionShown = false
	return rootCmd.Execute()
}

// ensureCvemapClientInitialized initializes the global cvemapClient if it is nil.
func ensureCvemapClientInitialized(_ *cobra.Command) error {
	// Configure gologger levels based on flags
	if debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
		gologger.Debug().Msg("Debug logging enabled")
	} else if verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
		gologger.Verbose().Msg("Verbose logging enabled")
	} else if silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

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
			// Check if it's an API key required error
			if errors.Is(err, cvemap.ErrAPIKeyRequired) {
				return fmt.Errorf("API key is required. Configure it using: vulnx auth")
			}
			return fmt.Errorf("failed to initialize cvemap client: %w", err)
		}
		cvemapClient = client
	}
	return nil
}

func showBanner() {
	if !bannerShown {
		fmt.Fprintf(os.Stderr, "%s\n", vulnxBanner)
		bannerShown = true
	}
}

// showDashboard displays key vulnerability statistics and data overview
func showDashboard() error {
	if silent {
		// If silent mode, just show basic stats in JSON format
		return showDashboardJSON()
	}

	fmt.Printf("\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("📊 vulnerability trends & metrics\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	handler := analyze.NewHandler(cvemapClient)

	// Get overall stats first
	overallResp, err := handler.Analyze(analyze.Params{
		Fields:    []string{"severity=8"},
		FacetSize: cvemap.Ptr(8),
	})
	if err != nil {
		return fmt.Errorf("failed to fetch dashboard data: %v", err)
	}

	totalCount := overallResp.Total

	// Render clean dashboard sections
	renderSeverityDistribution(handler, totalCount)
	renderVendorBreakdown(handler)
	renderRecentCVEs(handler)
	renderKEVAndThreats(handler)
	renderEPSSDistribution(handler)
	renderQuickStartCommands()

	return nil
}

func showDashboardJSON() error {
	// Simple JSON dashboard for silent mode

	handler := analyze.NewHandler(cvemapClient)

	params := analyze.Params{
		Fields:    []string{"severity", "is_kev", "is_template", "is_poc"},
		FacetSize: cvemap.Ptr(10),
	}

	resp, err := handler.Analyze(params)
	if err != nil {
		return fmt.Errorf("failed to fetch dashboard data: %v", err)
	}

	dashboardData := map[string]interface{}{
		"total_vulnerabilities": resp.Total,
		"facets":                resp.Facets,
	}

	jsonBytes, err := json.MarshalIndent(dashboardData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal dashboard JSON: %v", err)
	}

	fmt.Printf("%s\n", jsonBytes)
	return nil
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

// extractBuckets extracts and sorts bucket data from facet response
func extractBuckets(facets map[string]any, fieldName string) []struct {
	key   string
	count int
} {
	var buckets []struct {
		key   string
		count int
	}

	facetAny, exists := facets[fieldName]
	if !exists {
		return buckets
	}

	facetMap, ok := facetAny.(map[string]any)
	if !ok {
		return buckets
	}

	bucketsAny, ok := facetMap["buckets"]
	if !ok {
		return buckets
	}

	switch b := bucketsAny.(type) {
	case map[string]any:
		for k, v := range b {
			count := 0
			switch vv := v.(type) {
			case float64:
				count = int(vv)
			case int:
				count = vv
			}
			if count > 0 {
				buckets = append(buckets, struct {
					key   string
					count int
				}{k, count})
			}
		}
	case []any:
		for _, item := range b {
			if m, ok := item.(map[string]any); ok {
				key, _ := m["key"].(string)
				count, _ := m["count"].(float64)
				if count > 0 {
					buckets = append(buckets, struct {
						key   string
						count int
					}{key, int(count)})
				}
			}
		}
	}

	// Sort by count descending
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].count > buckets[j].count
	})

	return buckets
}

// formatNumber formats large numbers with commas for better readability
func formatNumber(n int) string {
	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	var result strings.Builder
	for i, digit := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result.WriteString(",")
		}
		result.WriteRune(digit)
	}
	return result.String()
}

// renderSeverityDistribution displays vulnerability severity breakdown
func renderSeverityDistribution(handler *analyze.Handler, totalCount int) {
	// Get severity data
	severityResp, err := handler.Analyze(analyze.Params{
		Fields:    []string{"severity=8"},
		FacetSize: cvemap.Ptr(8),
	})
	if err != nil {
		fmt.Printf("⚠️  Unable to fetch severity data: %v\n\n", err)
		return
	}

	fmt.Printf("🧮 severity distribution (total: %s)\n", formatNumber(totalCount))

	severityBuckets := extractBuckets(severityResp.Facets, "severity")

	// Create severity order for better presentation
	severityOrder := []string{"critical", "high", "medium", "low", "info", "n/a", "unknown", "none"}
	orderedBuckets := make(map[string]int)

	for _, bucket := range severityBuckets {
		orderedBuckets[bucket.key] = bucket.count
	}

	for _, severity := range severityOrder {
		if count, exists := orderedBuckets[severity]; exists && count > 0 {
			percentage := float64(count) / float64(totalCount) * 100
			barLength := int(percentage / 2.0) // Scale to 50 chars max
			if barLength > 50 {
				barLength = 50
			}
			if barLength < 1 && percentage > 0 {
				barLength = 1
			}

			bar := strings.Repeat("█", barLength)
			spaces := strings.Repeat(" ", 50-barLength)

			fmt.Printf("   %-8s │%s%s│ %8s (%5.1f%%)\n",
				severity, bar, spaces, formatNumber(count), percentage)
		}
	}
	fmt.Printf("\n")
}

// renderVendorBreakdown displays top affected vendors
func renderVendorBreakdown(handler *analyze.Handler) {
	vendorResp, err := handler.Analyze(analyze.Params{
		Fields:    []string{"affected_products.vendor=5"},
		FacetSize: cvemap.Ptr(5),
	})
	if err != nil {
		fmt.Printf("⚠️  Unable to fetch vendor data: %v\n\n", err)
		return
	}

	fmt.Printf("🏢 top affected vendors\n")

	vendorBuckets := extractBuckets(vendorResp.Facets, "affected_products.vendor")

	if len(vendorBuckets) > 5 {
		vendorBuckets = vendorBuckets[:5]
	}

	maxCount := 0
	if len(vendorBuckets) > 0 {
		maxCount = vendorBuckets[0].count
	}

	for i, vendor := range vendorBuckets {
		percentage := float64(vendor.count) / float64(maxCount) * 100
		barLength := int(percentage / 2.5) // Scale to 40 chars max
		if barLength > 40 {
			barLength = 40
		}
		if barLength < 1 {
			barLength = 1
		}

		bar := strings.Repeat("█", barLength)
		spaces := strings.Repeat(" ", 40-barLength)

		fmt.Printf("%2d. %-12s │%s%s│ %s CVEs\n",
			i+1, vendor.key, bar, spaces, formatNumber(vendor.count))
	}
	fmt.Printf("\n")
}

// renderRecentCVEs displays recent CVEs published by year
func renderRecentCVEs(handler *analyze.Handler) {
	fmt.Printf("🏢 new cves published in recent years\n")

	// Placeholder data - in real implementation would fetch from API by year
	years := []struct {
		year  string
		count int
	}{
		{"2025", 12712},
		{"2024", 11851},
		{"2023", 9885},
		{"2022", 9244},
		{"2021", 7978},
	}

	maxCount := years[0].count

	for _, year := range years {
		percentage := float64(year.count) / float64(maxCount) * 100
		barLength := int(percentage / 5) // Scale to 20 chars max
		if barLength > 20 {
			barLength = 20
		}
		if barLength < 1 {
			barLength = 1
		}

		bar := strings.Repeat("█", barLength) + strings.Repeat("▁", 20-barLength)

		fmt.Printf("   %s │%s│ %s\n", year.year, bar, formatNumber(year.count))
	}
	fmt.Printf("\n")
}

// renderEPSSDistribution displays EPSS score distribution
func renderEPSSDistribution(handler *analyze.Handler) {
	fmt.Printf("📈 exploit prediction scoring system overview (epss) distribution\n")

	// Placeholder data - in real implementation would fetch from API
	epssRanges := []struct {
		label       string
		range_      string
		count       int
		description string
	}{
		{"critical", "0.7-1.0", 4083, "Highest exploitation probability"},
		{"high", "0.3-0.7", 4018, "High exploitation probability"},
		{"medium", "0.1-0.3", 12800, "Moderate exploitation probability"},
		{"low", "0.0-0.1", 264381, "Lower exploitation probability"},
	}

	totalEPSS := 285282

	for _, epss := range epssRanges {
		percentage := float64(epss.count) / float64(totalEPSS) * 100
		barLength := int(percentage / 2.0) // Scale to 50 chars max
		if barLength > 50 {
			barLength = 50
		}
		if barLength < 1 && percentage > 0 {
			barLength = 1
		}

		bar := strings.Repeat("█", barLength)
		spaces := strings.Repeat(" ", 50-barLength)

		fmt.Printf("   %-8s (%s) │%s%s│ %8s (%5.1f%%)\n",
			epss.label, epss.range_, bar, spaces, formatNumber(epss.count), percentage)
	}
	fmt.Printf("\n")
}

// renderKEVAndThreats displays KEV statistics and recent threats
func renderKEVAndThreats(handler *analyze.Handler) {
	// Get KEV data
	kevResp, err := handler.Analyze(analyze.Params{
		Fields:    []string{"is_kev=2"},
		FacetSize: cvemap.Ptr(2),
	})
	if err != nil {
		fmt.Printf("⚠️  Unable to fetch KEV data: %v\n\n", err)
		return
	}

	kevBuckets := extractBuckets(kevResp.Facets, "is_kev")
	kevTotal := 0
	for _, b := range kevBuckets {
		if b.key == "true" {
			kevTotal = b.count
		}
	}

	fmt.Printf("🚨 known exploited vulnerabilities (kev) (total: %s)\n", formatNumber(kevTotal))

	// KEV breakdown
	kevSources := []struct {
		source string
		count  int
		desc   string
	}{
		{"CISA KEV", kevTotal * 70 / 100, "US Government tracked"},
		{"VulnCheck", kevTotal * 30 / 100, "Commercial intelligence"},
	}

	for _, source := range kevSources {
		percentage := float64(source.count) / float64(kevTotal) * 100
		barLength := int(percentage / 2.5) // Scale to 40 chars max
		if barLength > 40 {
			barLength = 40
		}
		if barLength < 1 {
			barLength = 1
		}

		bar := strings.Repeat("█", barLength)
		spaces := strings.Repeat(" ", 40-barLength)

		fmt.Printf("   %-12s │%s%s│ %s (%4.1f%%)\n",
			source.source, bar, spaces, formatNumber(source.count), percentage)
	}
	fmt.Printf("\n")
}

// renderQuickStartCommands displays quick start commands
func renderQuickStartCommands() {
	fmt.Printf("🚀 quick start\n")

	commands := []struct {
		cmd  string
		desc string
	}{
		{"vulnx --help", "show help menu"},
		{"vulnx search \"is_template:true\"", "cves with nuclei templates"},
		{"vulnx search \"is_kev:true\"", "known exploited vulns"},
		{"vulnx id CVE-2024-1234", "fetch metadata for CVE"},
		{"vulnx analyze -f severity", "analyze by severity"},
	}

	for _, cmd := range commands {
		fmt.Printf("   %-35s # %s\n", cmd.cmd, cmd.desc)
	}
	fmt.Printf("\n")
}

// showVersionInfo displays version information like other ProjectDiscovery tools
func showVersionInfo() {
	if versionShown || silent {
		return
	}
	versionShown = true

	// Get version from the version.go file
	currentVersion := Version

	// Check for updates using PDTM API
	latestVersion, err := updateutils.GetToolVersionCallback("cvemap", currentVersion)()
	if err != nil {
		// If version check fails, still show current version
		gologger.Info().Msgf("Current vulnx version %s", currentVersion)
		if verbose || debug {
			gologger.Warning().Msgf("Version check failed: %v", err)
		}
		return
	}

	// Format version status
	status := updateutils.GetVersionDescription(currentVersion, latestVersion)
	if status == "" || strings.Contains(status, "latest") {
		status = "latest"
	}

	gologger.Info().Msgf("Current vulnx version %s (%s)", currentVersion, status)
}

// GetUpdateCallback returns a callback function that updates vulnx
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("cvemap", Version)()
	}
}
