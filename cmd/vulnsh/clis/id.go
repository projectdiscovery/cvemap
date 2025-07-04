package clis

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/cvemap/pkg/tools/id"
	"github.com/projectdiscovery/cvemap/pkg/utils"
)

var ( //nolint

	idCmd = &cobra.Command{
		Use:   "id <vulnID>",
		Short: "Get vulnerability details by ID",
		Long: `Get vulnerability details by ID.

Global flags:
  --json     Output raw JSON (for piping, disables YAML output)
  --output   Write output to file in JSON format (error if file exists)
`,
		Example: `
# Get details for a specific vulnerability
vulnsh id CVE-2024-1234

# Output as JSON for piping
vulnsh id --json CVE-2024-1234

# Write output to a file (JSON)
vulnsh id --output vuln.json CVE-2024-1234
`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			vulnID := args[0]
			// Use the global cvemapClient
			handler := id.NewHandler(cvemapClient)
			vuln, err := handler.Get(vulnID)
			if err != nil {
				if errors.Is(err, cvemap.ErrNotFound) {
					gologger.Fatal().Msgf("Vulnerability not found: %s", vulnID)
				}
				gologger.Fatal().Msgf("Failed to fetch vulnerability: %s", err)
			}

			// Handle JSON and output file flags
			if jsonOutput || outputFile != "" {
				jsonBytes, err := json.Marshal(vuln)
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
					defer f.Close()
					if _, err := f.Write(jsonBytes); err != nil {
						gologger.Fatal().Msgf("Failed to write to output file: %s", err)
					}
					gologger.Info().Msgf("Wrote output to file: %s", outputFile)
					return
				}
				// Print to stdout
				os.Stdout.Write(jsonBytes)
				os.Stdout.Write([]byte("\n"))
				return
			}

			header := fmt.Sprintf("Vulnerability ID: %s", vulnID)
			var printErr error
			if noPager {
				printErr = utils.PrintColorYAMLNoPager(vuln, header)
			} else {
				printErr = utils.PrintColorYAML(vuln, header)
			}
			if printErr != nil {
				gologger.Fatal().Msgf("Failed to print colorized YAML: %s", printErr)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(idCmd)
}
