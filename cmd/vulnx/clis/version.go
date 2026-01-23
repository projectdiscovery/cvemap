package clis

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/spf13/cobra"
)

var (
	// Version can be set via ldflags during build
	Version = "v1.0.0"

	disableUpdateCheck bool

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "show vulnx version and check for updates",
		Long: `Show vulnx version and check for updates.

This command displays the current version of vulnx and checks if a newer version
is available. Update checking can be disabled with the --disable-update-check flag.
`,
		Example: `
# Show version and check for updates
vulnx version

# Show version without update check
vulnx version --disable-update-check
`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Override the root command's PersistentPreRunE to avoid client initialization
			if !silent {
				showBanner()
			}
			return nil // Don't initialize client for version command
		},
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	}
)

func showVersion() {
	gologger.Info().Msgf("Current vulnx version %s", Version)

	if disableUpdateCheck {
		return
	}

	// Check for latest version using PDTM API
	latestVersion, err := updateutils.GetToolVersionCallback("vulnx", Version)()
	if err != nil {
		if verbose || debug {
			gologger.Error().Msgf("vulnx version check failed: %v", err.Error())
		}
		return
	}

	// Show version comparison in the same format as vulnx
	description := updateutils.GetVersionDescription(Version, latestVersion)
	if description != "" {
		gologger.Info().Msgf("Current vulnx version %s %s", Version, description)

		// If there's a newer version available, provide helpful information
		if latestVersion != Version {
			gologger.Info().Msg("To update vulnx, use:")
			gologger.Info().Msg("vulnx --update  or  vulnx update")
			gologger.Info().Msg("Or install via pdtm: pdtm -u vulnx")
		}
	} else {
		gologger.Info().Msgf("Current vulnx version %s (latest)", Version)
	}
}

func init() {
	versionCmd.Flags().BoolVar(&disableUpdateCheck, "disable-update-check", false, "disable automatic update check")
	rootCmd.AddCommand(versionCmd)
}
