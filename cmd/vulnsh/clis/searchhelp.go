package clis

import (
	"fmt"
	"io"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/cvemap/pkg/tools/filters"
	"github.com/projectdiscovery/cvemap/pkg/utils"
)

var (
	searchHelpCmd = &cobra.Command{
		Use:     "help",
		Aliases: []string{"search:help", "searchhelp"},
		Short:   "Detailed help for the 'search' command with available filters",
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
  • Range facets for numeric/date buckets (e.g. epss_score, cve_created_at)
  • Optional result highlighting via --highlight

Example invocations:
  # Top 20 remote, exploitable KEV vulns published in 2024
  vulnsh search --limit 20 is_remote:true is_kev:true cve_created_at:2024

  # Facet by severity and tag
  vulnsh search --term-facets severity=5,tags=10 is_template:true

  # Numerical range facets and sorting
  vulnsh search --range-facets numeric:cvss_score:high:8:10 --sort-desc cvss_score "apache AND remote"

Below is a list of all fields that can be used in search queries. Fields marked
as "Facet" support term/range faceting. Fields marked "Sortable" can be used
with --sort-asc/--sort-desc.`

			// Use a pager when available
			w, closePager, err := utils.OpenPager()
			if err != nil {
				// Fallback to stdout wrapped as io.WriteCloser
				w = nopWriteCloser{Writer: cmd.OutOrStdout()}
				closePager = func() error { return nil }
			}
			defer closePager()

			fmt.Fprintln(w, overview)
			fmt.Fprintln(w, strings.Repeat("-", 120))

			// 2. Fetch filters via handler
			h := filters.NewHandler(cvemapClient)
			fltrs, err := h.List()
			if err != nil {
				gologger.Fatal().Msgf("Failed to fetch vulnerability filters: %s", err)
			}

			// 3. Render summary table
			tbl := table.NewWriter()
			tbl.SetOutputMirror(w)
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

			// 4. Detailed sections for enum_values / examples
			fmt.Fprintln(w, "\nADDITIONAL FIELD DETAILS")
			fmt.Fprintln(w, strings.Repeat("-", 120))
			for _, f := range fltrs {
				if len(f.EnumValues) == 0 && len(f.Examples) == 0 {
					continue
				}
				fmt.Fprintf(w, "\n%s\n", strings.ToUpper(f.Field))
				if len(f.EnumValues) > 0 {
					fmt.Fprintf(w, "  Enum Values : %s\n", strings.Join(f.EnumValues, ", "))
				}
				if len(f.Examples) > 0 {
					fmt.Fprintf(w, "  Examples    : %s\n", strings.Join(f.Examples, ", "))
				}
			}
		},
	}
)

func boolToYN(b bool) string {
	if b {
		return "Y"
	}
	return "-"
}

// nopWriteCloser wraps an io.Writer to satisfy io.WriteCloser when no pager is used.
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
