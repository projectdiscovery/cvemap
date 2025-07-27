package clis

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/spf13/cobra"
)

var (
	disableUpdateCheckForUpdate bool
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "update vulnx to latest version",
	Long: `Update vulnx to the latest version.

This command checks for the latest version of vulnx and downloads it if available.
Update checking can be disabled with the --disable-update-check flag.

Examples:
  vulnx update
  vulnx update --disable-update-check`,
	Run: func(cmd *cobra.Command, args []string) {
		if !disableUpdateCheckForUpdate && !silent {
			showBanner()
		}
		runUpdate()
	},
}

func runUpdate() {
	if disableUpdateCheckForUpdate {
		gologger.Info().Msg("Update check is disabled")
		return
	}

	gologger.Info().Msg("Checking for vulnx updates...")

	// Use cvemap name temporarily until server-side support is added for vulnx
	// TODO: Change "cvemap" to "vulnx" once server-side support is implemented
	updateutils.GetUpdateToolCallback("cvemap", Version)()
}

func init() {
	updateCmd.Flags().BoolVar(&disableUpdateCheckForUpdate, "disable-update-check", false, "disable automatic update check")
	rootCmd.AddCommand(updateCmd)
}
