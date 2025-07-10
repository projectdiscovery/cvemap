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
	searchHelpCmd = &cobra.Command{
		Use:     "help",
		Aliases: []string{"search:help", "searchhelp"},
		Short:   "detailed help for the 'search' command with available filters",
		Run: func(cmd *cobra.Command, args []string) {
			// Defensive: ensure cvemapClient is initialized if not already
			if cvemapClient == nil {
				if err := ensureCvemapClientInitialized(cmd); err != nil {
					gologger.Fatal().Msgf("Failed to initialize cvemap client: %s", err)
				}
			}
			// 1. Print high-level overview of the search feature
			overview := `SEARCH COMMAND — OVERVIEW

The search command provides powerful full-text and faceted search across the entire
ProjectDiscovery Vulnerability Database. It supports:
  • Lucene-style query syntax (e.g. cvss_score:>7 severity:critical)
  • Sorting (ascending / descending) on any sortable field
  • Pagination via limit / offset
  • Field selection to minimise payload size
  • Term facets for categorical aggregations (e.g. tags, severity)

Example invocations:
  # Top 20 remote, exploitable KEV vulns published in 2024
  vulnx search --limit 20 "is_remote:true && is_kev:true && cve_created_at:>2024"

  # Facet by severity and tag
  vulnx search --term-facets severity=5,tags=10 is_template:true

  # Sort by CVSS score with filtering
  vulnx search --sort-desc cvss_score "apache && is_remote:true"

Below is a list of all fields that can be used in search queries. Fields marked
as "Facet" support term/range faceting. Fields marked "Sortable" can be used
with --sort-asc/--sort-desc.`

			// Print overview
			fmt.Println(overview)
			fmt.Println(strings.Repeat("-", 120))

			// Print command usage & flags (default Cobra output) before field table
			fmt.Println("COMMAND USAGE & FLAGS")
			fmt.Println(strings.Repeat("-", 120))
			fmt.Println(cmd.UsageString())

			// 2. Fetch filters via handler
			h := filters.NewHandler(cvemapClient)
			fltrs, err := h.List()
			if err != nil {
				gologger.Fatal().Msgf("Failed to fetch vulnerability filters: %s", err)
			}

			// 3. Render summary table
			tbl := table.NewWriter()
			tbl.SetStyle(table.StyleRounded)
			tbl.AppendHeader(table.Row{"Field", "Data Type", "Description", "Sortable", "Facet"})
			tbl.SetColumnConfigs([]table.ColumnConfig{
				{Name: "Description", WidthMax: 60},
			})
			for _, f := range fltrs {
				tbl.AppendRow(table.Row{
					f.Field,
					f.DataType,
					f.Description,
					boolToYN(f.CanSort),
					boolToYN(f.FacetPossible),
				})
			}
			tbl.Render()
		},
	}
)

func boolToYN(b bool) string {
	if b {
		return "Y"
	}
	return "-"
}
