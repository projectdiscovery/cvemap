package clis

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"

	"github.com/jedib0t/go-pretty/v6/table"
	analyzetool "github.com/projectdiscovery/cvemap/pkg/tools/analyze"
)

var (
	// Flag placeholders – defined in init()
	analyzeFields    []string
	analyzeFacetSize int
	analyzeQuery     string

	analyzeCmd = &cobra.Command{
		Use:   "analyze",
		Short: "Group vulnerabilities by one or more fields using term facets",
		Long: `Group vulnerabilities by one or more fields using term facets.

The command internally leverages the Vulnerability Search API's term-facet
aggregation capabilities. It sets the response fields to "doc_id" and limit to
1 to minimise payload size – only the facet buckets are required for analyze
operations.

Examples:
  # Analyze by severity
  vulnx analyze -f severity

  # Analyze by vendor & product but only for templates with planned/covered coverage
  vulnx analyze -f affected_products.vendor,affected_products.product -q 'template_coverage:planned || template_coverage:covered'

Global flags:
  --json / -j   Output raw JSON (for piping, disables YAML output)
  --output / -o Write output to file in JSON format (error if file exists)
`,
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			// Support 'vulnx analyze help' by delegating to the dedicated help command.
			if len(args) > 0 && strings.ToLower(args[0]) == "help" {
				analyzeHelpCmd.Run(cmd, args)
				return
			}

			// Input validation
			if err := validateAnalyzeInputs(); err != nil {
				gologger.Fatal().Msgf("Invalid input: %s", err)
			}

			params := analyzetool.Params{
				Fields: analyzeFields,
			}
			if analyzeFacetSize > 0 {
				params.FacetSize = cvemap.Ptr(analyzeFacetSize)
			}
			if analyzeQuery != "" {
				params.Query = cvemap.Ptr(analyzeQuery)
			}

			// Use the global cvemapClient (initialised by rootCmd)
			handler := analyzetool.NewHandler(cvemapClient)
			resp, err := handler.Analyze(params)
			if err != nil {
				if errors.Is(err, cvemap.ErrNotFound) {
					gologger.Fatal().Msg("No results found for the provided facets")
				}
				gologger.Fatal().Msgf("Failed to perform analysis: %s", err)
			}

			// Handle JSON and output file flags (same behaviour as search)
			if jsonOutput || outputFile != "" {
				jsonBytes, err := json.Marshal(resp)
				if err != nil {
					gologger.Fatal().Msgf("Failed to marshal JSON: %s", err)
				}
				if outputFile != "" {
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
					gologger.Info().Msgf("Wrote output to file: %s", outputFile)
					return
				}
				if _, err := os.Stdout.Write(jsonBytes); err != nil {
					gologger.Error().Msgf("Failed to write JSON to stdout: %s", err)
				}
				if _, err := os.Stdout.Write([]byte("\n")); err != nil {
					gologger.Error().Msgf("Failed to write newline to stdout: %s", err)
				}
				return
			}

			// Render facet tables
			for facetName, facetAny := range resp.Facets {
				fmt.Printf("\nField: %s\n", facetName)

				tbl := table.NewWriter()
				tbl.SetOutputMirror(os.Stdout)
				tbl.SetStyle(table.StyleRounded)
				tbl.AppendHeader(table.Row{"Value", "Count"})

				// Attempt to coerce into expected structure
				facetMap, ok := facetAny.(map[string]any)
				if !ok {
					fmt.Printf("Warning: Unable to parse facet data for field '%s'\n", facetName)
					continue
				}

				bucketsAny, ok := facetMap["buckets"]
				if !ok {
					fmt.Printf("Warning: No buckets found for field '%s'\n", facetName)
					continue
				}

				hasData := false
				switch b := bucketsAny.(type) {
				case map[string]any:
					// Convert to slice and sort desc by count
					type kv struct {
						Key   string
						Count float64
					}
					var pairs []kv
					for k, v := range b {
						switch vv := v.(type) {
						case float64:
							pairs = append(pairs, kv{k, vv})
							hasData = true
						case int:
							pairs = append(pairs, kv{k, float64(vv)})
							hasData = true
						}
					}
					sort.Slice(pairs, func(i, j int) bool { return pairs[i].Count > pairs[j].Count })
					for _, p := range pairs {
						tbl.AppendRow(table.Row{p.Key, int(p.Count)})
					}
				case []any:
					for _, item := range b {
						if m, ok := item.(map[string]any); ok {
							key, _ := m["key"].(string)
							count, _ := m["count"].(float64)
							tbl.AppendRow(table.Row{key, int(count)})
							hasData = true
						}
					}
				}

				// Handle missing as "UNASSIGNED"
				if missAny, ok := facetMap["missing"]; ok {
					if mCount, ok2 := missAny.(float64); ok2 && mCount > 0 {
						tbl.AppendRow(table.Row{"UNASSIGNED", int(mCount)})
						hasData = true
					}
				}

				if hasData {
					tbl.Render()
				} else {
					fmt.Printf("No data found for field '%s'\n", facetName)
				}
			}
		},
	}
)

// validateAnalyzeInputs performs input validation for analyze command
func validateAnalyzeInputs() error {
	// Validate fields
	if len(analyzeFields) == 0 {
		return fmt.Errorf("at least one --fields value is required")
	}

	// Validate facet size
	if analyzeFacetSize < 1 || analyzeFacetSize > 1000 {
		return fmt.Errorf("facet-size must be between 1 and 1000")
	}

	// Validate output file path if specified
	if outputFile != "" {
		if !strings.HasSuffix(outputFile, ".json") {
			return fmt.Errorf("output file must have .json extension")
		}
	}

	return nil
}

func init() { // Register flags and add command to rootCmd
	analyzeCmd.Flags().StringSliceVarP(&analyzeFields, "fields", "f", nil, "Fields to calculate (comma-separated)")
	analyzeCmd.Flags().IntVar(&analyzeFacetSize, "facet-size", 10, "Number of facet buckets to return")
	analyzeCmd.Flags().StringVarP(&analyzeQuery, "query", "q", "", "Query to filter results")
	analyzeCmd.SetHelpFunc(analyzeHelpCmd.Run)

	rootCmd.AddCommand(analyzeCmd)
}
