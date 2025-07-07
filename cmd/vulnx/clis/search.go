package clis

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/cvemap/pkg/tools/renderer"
	searchtool "github.com/projectdiscovery/cvemap/pkg/tools/search"
)

var (
	// Flag placeholders – defined in init()
	searchLimit       int
	searchOffset      int
	searchSortAsc     string
	searchSortDesc    string
	searchFields      []string
	searchTermFacets  []string
	searchRangeFacets []string
	searchHighlight   bool
	searchFacetSize   int

	// Security-focused layout for CLI rendering
	defaultLayoutJSON = `[
		{
			"line": 1,
			"format": "[{doc_id}] {severity} - {title}",
			"omit_if": []
		},
		{
			"line": 2,
			"format": "  ↳ Priority: {research_priority} | {exploit_status} | Vuln Age: {age_urgency}",
			"omit_if": []
		},
		{
			"line": 3,
			"format": "  ↳ CVSS: {cvss_enhanced} | EPSS: {epss_enhanced} | KEV: {kev_enhanced}",
			"omit_if": ["cvss_score == 0", "epss_score == 0"]
		},
		{
			"line": 4,
			"format": "  ↳ Exposure: {exposure} | Vendors: {vendors} | Products: {products}",
			"omit_if": ["exposure == 0", "vendors.length == 0", "products.length == 0"]
		},
		{
			"line": 5,
			"format": "  ↳ Patch: {patch} | POCs: {poc_count} | Nuclei Template: {template} | HackerOne: {hackerone}",
			"omit_if": []
		},
		{
			"line": 6,
			"format": "  ↳ Template Authors: {authors}",
			"omit_if": ["authors.length == 0"]
		}
	]`

	searchCmd = &cobra.Command{
		Use:   "search <query>",
		Short: "Search vulnerabilities using the Vulnerability search API",
		Long: `Search vulnerabilities using the Vulnerability search API.

Global flags:
  --json      Output raw JSON (for piping, disables CLI output)
  --output    Write output to file in JSON format (error if file exists)
  --no-color  Disable colored output (colors are auto-disabled for non-terminal output)
`,
		Example: `
# Search help
vulnx help search

# Basic search for only KEV vulnerabilities
vulnx search is_kev:true

# Output as JSON for piping
vulnx search --json is_kev:true

# Write output to a file (JSON)
vulnx search --output results.json is_kev:true

# Search and request term facets (tags and severity)
vulnx search --term-facets tags=10,severity=4 is_remote:true

# Search and request range facets:
#   – CVE created in 2024
#   – EPS score "high" bucket (0.9-1.0)
vulnx search \
	--range-facets date:cve_created_at:2024:2024-01:2024-12 \
	--range-facets numeric:epss_score:high:0.9:1.0 \
	is_poc:true

# Combine term and range facets
vulnx search \
	--term-facets tags=10 \
	--range-facets numeric:epss_score:medium:0.4:0.9 \
	cvss_score:>7
		`,
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			query := strings.Join(args, " ")
			query = strings.TrimSpace(query)

			// Input validation
			if err := validateSearchInputs(); err != nil {
				gologger.Fatal().Msgf("Invalid input: %s", err)
			}

			params := cvemap.SearchParams{}

			if searchLimit > 0 {
				params.Limit = cvemap.Ptr(searchLimit)
			}
			if searchOffset > 0 {
				params.Offset = cvemap.Ptr(searchOffset)
			}
			if searchSortAsc != "" {
				params.SortAsc = cvemap.Ptr(searchSortAsc)
			}
			if searchSortDesc != "" {
				params.SortDesc = cvemap.Ptr(searchSortDesc)
			}
			if len(searchFields) > 0 {
				params.Fields = searchFields
			}
			if len(searchTermFacets) > 0 {
				params.TermFacets = searchTermFacets
				for i, facet := range params.TermFacets {
					if strings.Contains(facet, "=") {
						params.TermFacets[i] = strings.ReplaceAll(facet, "=", ":")
					}
				}
			}
			if len(searchRangeFacets) > 0 {
				params.RangeFacets = searchRangeFacets
			}
			if searchHighlight {
				params.Highlight = cvemap.Ptr(true)
			}
			if searchFacetSize > 0 {
				params.FacetSize = cvemap.Ptr(searchFacetSize)
			}
			// Positional query string (optional)
			if query != "" {
				params.Query = cvemap.Ptr(query)
			}

			// Use the global cvemapClient
			handler := searchtool.NewHandler(cvemapClient)
			resp, err := handler.Search(params)
			if err != nil {
				if errors.Is(err, cvemap.ErrNotFound) {
					gologger.Fatal().Msgf("No results found for query: %s", query)
				}
				gologger.Fatal().Msgf("Failed to perform search: %s", err)
			}
			if resp.Count == 0 {
				if query != "" {
					gologger.Info().Msgf("No results found for query: %s", query)
				} else {
					gologger.Info().Msgf("No results found")
				}
				return
			}

			// Handle JSON and output file flags
			if jsonOutput || outputFile != "" {
				jsonBytes, err := json.Marshal(resp)
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
					gologger.Info().Msgf("Wrote output to file: %s", outputFile)
					return
				}
				// Print to stdout
				if _, err := os.Stdout.Write(jsonBytes); err != nil {
					gologger.Error().Msgf("Failed to write JSON output: %s", err)
				}
				if _, err := os.Stdout.Write([]byte("\n")); err != nil {
					gologger.Error().Msgf("Failed to write newline: %s", err)
				}
				return
			}

			// Default CLI renderer format
			layout, err := renderer.ParseLayout([]byte(defaultLayoutJSON))
			if err != nil {
				gologger.Fatal().Msgf("Failed to parse layout: %s", err)
			}

			// Convert vulnerabilities to entries
			entries := make([]*renderer.Entry, 0, len(resp.Results))
			for _, vuln := range resp.Results {
				entry := renderer.FromVulnerability(&vuln)
				if entry != nil {
					entries = append(entries, entry)
				}
			}

			// Configure colors based on flags and terminal detection
			var colors *renderer.ColorConfig
			if noColor || !renderer.IsTerminal() {
				colors = renderer.NoColorConfig()
			} else {
				colors = renderer.DefaultColorConfig()
			}

			// Render output with colors
			output := renderer.RenderWithColors(entries, layout, resp.Total, resp.Count, colors)
			fmt.Print(output)
		},
	}
)

// validateSearchInputs performs input validation for search command
func validateSearchInputs() error {
	// Validate limit
	if searchLimit < 0 || searchLimit > 10000 {
		return fmt.Errorf("limit must be between 0 and 10000")
	}

	// Validate offset
	if searchOffset < 0 {
		return fmt.Errorf("offset must be non-negative")
	}

	// Validate conflicting sort options
	if searchSortAsc != "" && searchSortDesc != "" {
		return fmt.Errorf("cannot specify both --sort-asc and --sort-desc")
	}

	// Validate facet size
	if searchFacetSize < 1 || searchFacetSize > 1000 {
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
	searchCmd.Flags().IntVarP(&searchLimit, "limit", "n", 10, "Number of results to return (0 = server default)")
	searchCmd.Flags().IntVar(&searchOffset, "offset", 0, "Offset for pagination (start position)")
	searchCmd.Flags().StringVar(&searchSortAsc, "sort-asc", "", "Field to sort ascending")
	searchCmd.Flags().StringVar(&searchSortDesc, "sort-desc", "", "Field to sort descending")
	searchCmd.Flags().StringSliceVar(&searchFields, "fields", nil, "Fields to include in the response (comma-separated)")
	searchCmd.Flags().StringSliceVar(&searchTermFacets, "term-facets", nil, "Term facets to calculate (comma-separated)")
	searchCmd.Flags().StringSliceVar(&searchRangeFacets, "range-facets", nil, "Range facets to calculate (comma-separated)")
	searchCmd.Flags().BoolVar(&searchHighlight, "highlight", false, "Return search highlights where supported")
	searchCmd.Flags().IntVar(&searchFacetSize, "facet-size", 10, "Number of facet buckets to return")
	searchCmd.SetHelpFunc(searchHelpCmd.Run)

	rootCmd.AddCommand(searchCmd)
}
