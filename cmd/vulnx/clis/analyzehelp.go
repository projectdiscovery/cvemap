package clis

import (
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/vulnx/pkg/tools/filters"
)

var (
	analyzeHelpCmd = &cobra.Command{
		Use:     "help",
		Aliases: []string{"analyze:help", "analyzehelp"},
		Short:   "detailed help for the 'analyze' command with facet-capable fields",
		Run: func(cmd *cobra.Command, args []string) {
			// Defensive: ensure vulnxClient is initialized if not already
			if vulnxClient == nil {
				if err := ensureVulnxClientInitialized(cmd); err != nil {
					gologger.Fatal().Msgf("Failed to initialize vulnx client: %s", err)
				}
			}

			// Print command usage & flags (default Cobra output) before examples
			fmt.Println(cmd.UsageString())

			// Fetch filters via handler
			h := filters.NewHandler(vulnxClient)
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
