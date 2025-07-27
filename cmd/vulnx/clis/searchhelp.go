package clis

import (
	"fmt"

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
			// Print command usage & flags (default Cobra output) before field table
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
