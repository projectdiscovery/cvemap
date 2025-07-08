package clis

import (
	"fmt"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/cvemap/pkg/tools/filters"
)

var (
	groupbyHelpCmd = &cobra.Command{
		Use:     "help",
		Aliases: []string{"analyze:help", "analyzehelp"},
		Short:   "Detailed help for the 'analyze' command with facet-capable fields",
		Run: func(cmd *cobra.Command, args []string) {
			// Defensive: ensure cvemapClient is initialized if not already
			if cvemapClient == nil {
				if err := ensureCvemapClientInitialized(cmd); err != nil {
					gologger.Fatal().Msgf("Failed to initialize cvemap client: %s", err)
				}
			}

			overview := `ANALYZE COMMAND — OVERVIEW

The analyze command provides a convenient shorthand for performing
"GROUP BY"-style aggregations over the ProjectDiscovery Vulnerability Database.
It leverages the Search API's term-facet capability internally, automatically
setting 'fields' to 'doc_id' and 'limit' to 1.

It supports:
  • --fields / -f   Comma-separated list of facet fields (required)
  • --facet-size    Default bucket size (overridden per-field via field=size)
  • --query  / -q   Optional Lucene-style search filter before aggregation

Example invocations:
  # Group by severity (top 5 buckets)
  vulnx analyze -f severity=5

  # Group by vendor and product for templates with planned / covered coverage
  vulnx analyze -f affected_products.vendor,affected_products.product \
                -q 'template_coverage:planned || template_coverage:covered'
`

			// Print overview
			fmt.Println(overview)
			fmt.Println(strings.Repeat("-", 120))

			// Print command usage & flags (default Cobra output) before examples
			fmt.Println("COMMAND USAGE & FLAGS")
			fmt.Println(strings.Repeat("-", 120))
			fmt.Println(cmd.UsageString())

			// Fetch filters via handler
			h := filters.NewHandler(cvemapClient)
			fltrs, err := h.List()
			if err != nil {
				gologger.Fatal().Msgf("Failed to fetch vulnerability filters: %s", err)
			}

			// Render table with only facet-capable fields
			tbl := table.NewWriter()
			tbl.SetStyle(table.StyleRounded)
			tbl.AppendHeader(table.Row{"Field", "Data Type", "Description", "Facet"})
			tbl.SetColumnConfigs([]table.ColumnConfig{
				{Name: "Description", WidthMax: 60},
			})
			for _, f := range fltrs {
				// Only include facet-capable string/boolean fields; skip numeric and datetime
				if !f.FacetPossible {
					continue
				}
				if f.DataType == "number" || f.DataType == "datetime" {
					continue
				}
				tbl.AppendRow(table.Row{
					f.Field,
					f.DataType,
					f.Description,
					boolToYN(f.FacetPossible),
				})
			}
			tbl.Render()
		},
	}
)
