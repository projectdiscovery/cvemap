package clis

import (
	"errors"
	"fmt"

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
		Args:  cobra.ExactArgs(1),
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
			header := fmt.Sprintf("Vulnerability ID: %s", vulnID)
			if err := utils.PrintColorYAML(vuln, header); err != nil {
				gologger.Fatal().Msgf("Failed to print colorized YAML: %s", err)
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(idCmd)
}
