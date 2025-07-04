package clis

import (
	"fmt"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/cvemap/pkg/tools/filters"
	"github.com/projectdiscovery/cvemap/pkg/utils"
)

var (
	groupbyHelpCmd = &cobra.Command{
		Use:     "help",
		Aliases: []string{"groupby:help", "groupbyhelp"},
		Short:   "Detailed help for the 'groupby' command with facet-capable fields",
		Run: func(cmd *cobra.Command, args []string) {
			// Defensive: ensure cvemapClient is initialized if not already
			if cvemapClient == nil {
				if err := ensureCvemapClientInitialized(cmd); err != nil {
					gologger.Fatal().Msgf("Failed to initialize cvemap client: %s", err)
				}
			}

			overview := `GROUPBY COMMAND — OVERVIEW

The groupby command provides a convenient shorthand for performing
"GROUP BY"-style aggregations over the ProjectDiscovery Vulnerability Database.
It leverages the Search API's term-facet capability internally, automatically
setting 'fields' to 'doc_id' and 'limit' to 1.

It supports:
  • --fields / -f   Comma-separated list of facet fields (required)
  • --facet-size    Default bucket size (overridden per-field via field=size)
  • --query  / -q   Optional Lucene-style search filter before aggregation

Example invocations:
  # Group by severity (top 5 buckets)
  vulnsh groupby -f severity=5

  # Group by vendor and product for templates with planned / covered coverage
  vulnsh groupby -f affected_products.vendor,affected_products.product \
                -q 'template_coverage:planned || template_coverage:covered'
`

			// Use a pager when available
			w, closePager, err := utils.OpenPager(noPager)
			if err != nil {
				w = nopWriteCloser{Writer: cmd.OutOrStdout()}
				closePager = func() error { return nil }
			}
			defer func() { _ = closePager() }()

			// Print overview
			if _, err := fmt.Fprintln(w, overview); err != nil {
				gologger.Error().Msgf("Failed to write overview: %s", err)
			}
			if _, err := fmt.Fprintln(w, strings.Repeat("-", 120)); err != nil {
				gologger.Error().Msgf("Failed to write separator: %s", err)
			}

			// Print command usage & flags (default Cobra output) before examples
			if _, err := fmt.Fprintln(w, "COMMAND USAGE & FLAGS"); err != nil {
				gologger.Error().Msgf("Failed to write command usage: %s", err)
			}
			if _, err := fmt.Fprintln(w, strings.Repeat("-", 120)); err != nil {
				gologger.Error().Msgf("Failed to write separator: %s", err)
			}
			if _, err := fmt.Fprintln(w, cmd.UsageString()); err != nil {
				gologger.Error().Msgf("Failed to write usage string: %s", err)
			}

			// Fetch filters via handler
			h := filters.NewHandler(cvemapClient)
			fltrs, err := h.List()
			if err != nil {
				gologger.Fatal().Msgf("Failed to fetch vulnerability filters: %s", err)
			}

			// Render table with only facet-capable fields
			tbl := table.NewWriter()
			tbl.SetOutputMirror(w)
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

// Note: nopWriteCloser is defined in searchhelp.go and reused here
