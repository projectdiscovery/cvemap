package clis

import (
	"github.com/spf13/cobra"

	"time"

	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	_ "embed"
	"strings"

	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"

	"os"

	"github.com/mark3labs/mcp-go/server"
	"github.com/projectdiscovery/cvemap/pkg/tools"
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

	// Add global noPager flag
	noPager bool

	// Add global json and output flags
	jsonOutput bool
	outputFile string

	// Add global silent flag
	silent bool

	// Add global no-color flag
	noColor bool

	// Track if the banner has already been shown for this invocation
	bannerShown bool

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

	// Add persistent no-pager flag
	rootCmd.PersistentFlags().BoolVar(&noPager, "no-pager", false, "Disable use of pager for output")

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
		if verbose {
			gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		}
		if debug {
			gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
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
