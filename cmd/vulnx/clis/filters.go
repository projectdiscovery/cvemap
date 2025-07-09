package clis

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/cvemap/pkg/tools/filters"
)

var (
	filtersCmd = &cobra.Command{
		Use:   "filters",
		Short: "List all available search filters",
		Long: `List all available search filters supported by the Vulnerability search API.

This command shows detailed information about all fields that can be used in search queries, 
including their data types, descriptions, examples, and enum values.`,
		Example: `
# List all available filters with detailed information
vulnx filters

# Output as JSON
vulnx filters --json

# Write filter information to a file
vulnx filters --output filters.json`,
		Run: func(cmd *cobra.Command, args []string) {
			// Use the filters handler to get available filters
			handler := filters.NewHandler(cvemapClient)
			filterList, err := handler.List()
			if err != nil {
				gologger.Fatal().Msgf("Failed to fetch vulnerability filters: %s", err)
			}

			if len(filterList) == 0 {
				gologger.Info().Msg("No filters available")
				return
			}

			// Handle JSON and output file flags
			if jsonOutput || outputFile != "" {
				jsonBytes, err := json.Marshal(filterList)
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
					gologger.Info().Msgf("Wrote filter information to file: %s", outputFile)
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

			// Show detailed information
			for i, filter := range filterList {
				if i > 0 {
					fmt.Println(strings.Repeat("-", 80))
				}
				fmt.Printf("Field: %s\n", filter.Field)
				fmt.Printf("Data Type: %s\n", filter.DataType)
				fmt.Printf("Description: %s\n", filter.Description)
				fmt.Printf("Can Sort: %s\n", boolToYesNo(filter.CanSort))
				fmt.Printf("Facet Possible: %s\n", boolToYesNo(filter.FacetPossible))
				if filter.SearchAnalyzer != "" {
					fmt.Printf("Search Analyzer: %s\n", filter.SearchAnalyzer)
				}
				if len(filter.Examples) > 0 {
					fmt.Printf("Examples: %s\n", strings.Join(filter.Examples, ", "))
				}
				if len(filter.EnumValues) > 0 {
					fmt.Printf("Enum Values: %s\n", strings.Join(filter.EnumValues, ", "))
				}
				fmt.Println()
			}

			// Print total count at the bottom
			fmt.Printf("Total: %d filters available\n", len(filterList))
		},
	}
)

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func init() {
	rootCmd.AddCommand(filtersCmd)
}
