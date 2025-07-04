package clis

import (
	"github.com/spf13/cobra"

	"time"

	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"strings"

	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/retryablehttp-go"
)

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

	rootCmd = &cobra.Command{
		Use:   "vulnsh",
		Short: "vulnsh — The Swiss Army knife for vulnerability intel",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return ensureCvemapClientInitialized(cmd)
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
}

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}

// ensureCvemapClientInitialized initializes the global cvemapClient if it is nil.
func ensureCvemapClientInitialized(cmd *cobra.Command) error {
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
