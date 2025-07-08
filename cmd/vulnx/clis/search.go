package clis

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
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
	searchDetailed    bool

	// Filter flags
	filterProduct         []string
	filterVendor          []string
	filterExcludeProduct  []string
	filterExcludeVendor   []string
	filterSeverity        []string
	filterExcludeSeverity []string
	filterCPE             string
	filterAssignee        []string
	filterVulnStatus      string
	filterVulnAge         string
	filterKevOnly         string
	filterTemplate        string
	filterPOC             string
	filterHackerOne       string
	filterRemoteExploit   string

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
			"format": "{exposure_vendors_products}",
			"omit_if": []
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
  --detailed  Show detailed vulnerability information
`,
		Example: `
# Search help
vulnx help search

# Basic search for only KEV vulnerabilities
vulnx search "is_kev:true"

# Search with detailed information
vulnx search --detailed "xss"

# Output as JSON for piping
vulnx search --json "is_kev:true"

# Write output to a file (JSON)
vulnx search --output results.json "is_kev:true"

# Search and request term facets (tags and severity)
vulnx search --term-facets tags=10,severity=4 "is_remote:true"

# Search and request range facets:
#   – CVE created in 2024
#   – EPS score "high" bucket (0.9-1.0)
vulnx search \
	--range-facets date:cve_created_at:2024:2024-01:2024-12 \
	--range-facets numeric:epss_score:high:0.9:1.0 \
	"is_poc:true"

# Combine term and range facets
vulnx search \
	--term-facets tags=10 \
	--range-facets numeric:epss_score:medium:0.4:0.9 \
	"cvss_score:>7"
		`,
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			query := strings.Join(args, " ")
			query = strings.TrimSpace(query)

			// Input validation
			if err := validateSearchInputs(); err != nil {
				gologger.Fatal().Msgf("Invalid input: %s", err)
			}

			// Build filter query from flags
			filterQuery, err := buildFilterQuery()
			if err != nil {
				gologger.Fatal().Msgf("Failed to build filter query: %s", err)
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

			// Combine user query with filter query
			finalQuery := query
			if filterQuery != "" {
				if finalQuery != "" {
					finalQuery = fmt.Sprintf("(%s) && (%s)", finalQuery, filterQuery)
				} else {
					finalQuery = filterQuery
				}
			}

			// Set final query
			if finalQuery != "" {
				params.Query = cvemap.Ptr(finalQuery)
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
			if searchDetailed {
				// Use detailed rendering for each entry (similar to 'id' command)
				for i, entry := range entries {
					// Add separator between multiple results
					if i > 0 {
						separator := strings.Repeat("─", 65)
						if colors != nil {
							fmt.Println(colors.ColorResultSeparator(separator))
						} else {
							fmt.Println(separator)
						}
						fmt.Println()
					}

					// Render detailed output for each entry
					result := renderer.RenderDetailed(entry, colors)
					fmt.Print(result)
				}

				// Show summary at the end
				fmt.Printf("\n")
				summaryLine := fmt.Sprintf("Showing %d out of %d total results", resp.Count, resp.Total)
				if colors != nil {
					fmt.Println(colors.ColorResultSeparator(summaryLine))
				} else {
					fmt.Println(summaryLine)
				}
			} else {
				// Use default layout rendering
				output := renderer.RenderWithColors(entries, layout, resp.Total, resp.Count, colors)
				fmt.Print(output)
			}
		},
	}
)

// buildFilterQuery constructs the filter query from all filter flags
func buildFilterQuery() (string, error) {
	var queryParts []string

	// Build product filter - search both vendor and product fields for better UX
	if len(filterProduct) > 0 {
		productQuery := buildProductQuery(filterProduct)
		queryParts = append(queryParts, productQuery)
	}

	// Build vendor filter - search both vendor and product fields for better UX
	if len(filterVendor) > 0 {
		vendorQuery := buildVendorQuery(filterVendor)
		queryParts = append(queryParts, vendorQuery)
	}

	// Build exclude product filter
	if len(filterExcludeProduct) > 0 {
		excludeQuery := buildNotInQuery("affected_products.product", filterExcludeProduct)
		queryParts = append(queryParts, excludeQuery)
	}

	// Build exclude vendor filter
	if len(filterExcludeVendor) > 0 {
		excludeQuery := buildNotInQuery("affected_products.vendor", filterExcludeVendor)
		queryParts = append(queryParts, excludeQuery)
	}

	// Build severity filter
	if len(filterSeverity) > 0 {
		severityQuery := buildInQuery("severity", filterSeverity)
		queryParts = append(queryParts, severityQuery)
	}

	// Build exclude severity filter
	if len(filterExcludeSeverity) > 0 {
		excludeQuery := buildNotInQuery("severity", filterExcludeSeverity)
		queryParts = append(queryParts, excludeQuery)
	}

	// Build CPE filter
	if filterCPE != "" {
		queryParts = append(queryParts, fmt.Sprintf("cpe:\"%s\"", filterCPE))
	}

	// Build assignee filter
	if len(filterAssignee) > 0 {
		assigneeQuery := buildInQuery("assignee_short_name", filterAssignee)
		queryParts = append(queryParts, assigneeQuery)
	}

	// Build vulnerability status filter
	if filterVulnStatus != "" {
		queryParts = append(queryParts, fmt.Sprintf("vuln_status:%s", filterVulnStatus))
	}

	// Build vulnerability age filter
	if filterVulnAge != "" {
		ageQuery, err := buildAgeQuery(filterVulnAge)
		if err != nil {
			return "", fmt.Errorf("invalid age filter: %w", err)
		}
		queryParts = append(queryParts, ageQuery)
	}

	// Build boolean filters
	if filterKevOnly != "" {
		if filterKevOnly == "true" {
			queryParts = append(queryParts, fmt.Sprintf("is_kev:%t", true))
		} else {
			queryParts = append(queryParts, fmt.Sprintf("is_kev:%t", false))
		}
	}

	if filterTemplate != "" {
		if filterTemplate == "true" {
			queryParts = append(queryParts, fmt.Sprintf("is_template:%t", true))
		} else {
			queryParts = append(queryParts, fmt.Sprintf("is_template:%t", false))
		}
	}

	if filterPOC != "" {
		if filterPOC == "true" {
			queryParts = append(queryParts, fmt.Sprintf("is_poc:%t", true))
		} else {
			queryParts = append(queryParts, fmt.Sprintf("is_poc:%t", false))
		}
	}

	if filterHackerOne != "" {
		if filterHackerOne == "true" {
			queryParts = append(queryParts, "hackerone.reports:>0")
		} else {
			queryParts = append(queryParts, "NOT hackerone.reports:>0")
		}
	}

	if filterRemoteExploit != "" {
		if filterRemoteExploit == "true" {
			queryParts = append(queryParts, fmt.Sprintf("is_remote:%t", true))
		} else {
			queryParts = append(queryParts, fmt.Sprintf("is_remote:%t", false))
		}
	}

	return strings.Join(queryParts, " && "), nil
}

// buildProductQuery builds a query that searches both vendor and product fields
// This provides better UX when users search for products like "apache"
func buildProductQuery(values []string) string {
	if len(values) == 0 {
		return ""
	}

	var parts []string
	for _, value := range values {
		// Search both vendor and product fields for each value
		productPart := fmt.Sprintf("affected_products.product:%s", value)
		vendorPart := fmt.Sprintf("affected_products.vendor:%s", value)
		parts = append(parts, fmt.Sprintf("(%s || %s)", productPart, vendorPart))
	}

	if len(parts) == 1 {
		return parts[0]
	}

	return fmt.Sprintf("(%s)", strings.Join(parts, " || "))
}

// buildVendorQuery builds a query that searches both vendor and product fields for vendors
func buildVendorQuery(values []string) string {
	if len(values) == 0 {
		return ""
	}

	var parts []string
	for _, value := range values {
		// Search both vendor and product fields for each value
		productPart := fmt.Sprintf("affected_products.product:%s", value)
		vendorPart := fmt.Sprintf("affected_products.vendor:%s", value)
		parts = append(parts, fmt.Sprintf("(%s || %s)", productPart, vendorPart))
	}

	if len(parts) == 1 {
		return parts[0]
	}

	return fmt.Sprintf("(%s)", strings.Join(parts, " || "))
}

// buildInQuery builds an OR query for multiple values
func buildInQuery(field string, values []string) string {
	if len(values) == 0 {
		return ""
	}

	if len(values) == 1 {
		return fmt.Sprintf("%s:%s", field, values[0])
	}

	var parts []string
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%s:%s", field, value))
	}

	return fmt.Sprintf("(%s)", strings.Join(parts, " || "))
}

// buildNotInQuery builds a NOT query for multiple values
func buildNotInQuery(field string, values []string) string {
	if len(values) == 0 {
		return ""
	}

	var parts []string
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("NOT %s:%s", field, value))
	}

	return fmt.Sprintf("(%s)", strings.Join(parts, " && "))
}

// buildAgeQuery builds age query with support for <, > operations
func buildAgeQuery(ageFilter string) (string, error) {
	ageFilter = strings.TrimSpace(ageFilter)

	if strings.HasPrefix(ageFilter, "<") {
		ageStr := strings.TrimSpace(ageFilter[1:])
		age, err := strconv.Atoi(ageStr)
		if err != nil {
			return "", fmt.Errorf("invalid age value: %s", ageStr)
		}
		return fmt.Sprintf("age_in_days:<%d", age), nil
	}

	if strings.HasPrefix(ageFilter, ">") {
		ageStr := strings.TrimSpace(ageFilter[1:])
		age, err := strconv.Atoi(ageStr)
		if err != nil {
			return "", fmt.Errorf("invalid age value: %s", ageStr)
		}
		return fmt.Sprintf("age_in_days:>%d", age), nil
	}

	// Exact age
	age, err := strconv.Atoi(ageFilter)
	if err != nil {
		return "", fmt.Errorf("invalid age value: %s", ageFilter)
	}
	return fmt.Sprintf("age_in_days:%d", age), nil
}

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
	// Existing flags
	searchCmd.Flags().IntVarP(&searchLimit, "limit", "n", 10, "Number of results to return (0 = server default)")
	searchCmd.Flags().IntVar(&searchOffset, "offset", 0, "Offset for pagination (start position)")
	searchCmd.Flags().StringVar(&searchSortAsc, "sort-asc", "", "Field to sort ascending")
	searchCmd.Flags().StringVar(&searchSortDesc, "sort-desc", "", "Field to sort descending")
	searchCmd.Flags().StringSliceVar(&searchFields, "fields", nil, "Fields to include in the response (comma-separated)")
	searchCmd.Flags().StringSliceVar(&searchTermFacets, "term-facets", nil, "Term facets to calculate (comma-separated)")
	searchCmd.Flags().StringSliceVar(&searchRangeFacets, "range-facets", nil, "Range facets to calculate (comma-separated)")
	searchCmd.Flags().BoolVar(&searchHighlight, "highlight", false, "Return search highlights where supported")
	searchCmd.Flags().IntVar(&searchFacetSize, "facet-size", 10, "Number of facet buckets to return")
	searchCmd.Flags().BoolVar(&searchDetailed, "detailed", false, "Show detailed vulnerability information (similar to 'id' command)")

	// Filter flags - String slice filters
	searchCmd.Flags().StringSliceVarP(&filterProduct, "product", "p", nil, "Filter by product (comma-separated)")
	searchCmd.Flags().StringSliceVar(&filterVendor, "vendor", nil, "Filter by vendor (comma-separated)")
	searchCmd.Flags().StringSliceVar(&filterExcludeProduct, "exclude-product", nil, "Exclude products (comma-separated)")
	searchCmd.Flags().StringSliceVar(&filterExcludeVendor, "exclude-vendor", nil, "Exclude vendors (comma-separated)")
	searchCmd.Flags().StringSliceVarP(&filterSeverity, "severity", "s", nil, "Filter by severity (comma-separated)")
	searchCmd.Flags().StringSliceVar(&filterExcludeSeverity, "exclude-severity", nil, "Exclude severities (comma-separated)")
	searchCmd.Flags().StringSliceVarP(&filterAssignee, "assignee", "a", nil, "Filter by assignee (comma-separated)")

	// Single value filters
	searchCmd.Flags().StringVarP(&filterCPE, "cpe", "c", "", "Filter by CPE string")
	searchCmd.Flags().StringVar(&filterVulnStatus, "vstatus", "", "Filter by vulnerability status (new, confirmed, unconfirmed, modified, rejected, unknown)")
	searchCmd.Flags().StringVar(&filterVulnAge, "vuln-age", "", "Filter by vulnerability age (supports <, >, exact: e.g., '5', '<10', '>30')")

	// Boolean filters with default to true when flag is present without value
	searchCmd.Flags().StringVar(&filterKevOnly, "kev-only", "", "Filter KEV (Known Exploited Vulnerabilities) only (true/false)")
	searchCmd.Flags().Lookup("kev-only").NoOptDefVal = "true"

	searchCmd.Flags().StringVarP(&filterTemplate, "template", "t", "", "Filter CVEs with Nuclei templates (true/false)")
	searchCmd.Flags().Lookup("template").NoOptDefVal = "true"

	searchCmd.Flags().StringVar(&filterPOC, "poc", "", "Filter CVEs with public POCs (true/false)")
	searchCmd.Flags().Lookup("poc").NoOptDefVal = "true"

	searchCmd.Flags().StringVar(&filterHackerOne, "hackerone", "", "Filter CVEs reported on HackerOne (true/false)")
	searchCmd.Flags().Lookup("hackerone").NoOptDefVal = "true"

	searchCmd.Flags().StringVar(&filterRemoteExploit, "remote-exploit", "", "Filter remotely exploitable CVEs (true/false)")
	searchCmd.Flags().Lookup("remote-exploit").NoOptDefVal = "true"

	searchCmd.SetHelpFunc(searchHelpCmd.Run)
	rootCmd.AddCommand(searchCmd)
}
