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

Note: Currently uses 'cvemap' for version checking until server-side support is added.
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
	gologger.Info().Msgf("vulnx version %s", Version)

	if disableUpdateCheck {
		return
	}

	// Use vulnx for version checks - pdtm now supports vulnx directly
	latestVersion, err := updateutils.GetToolVersionCallback("vulnx", Version)()
	if err != nil {
		if verbose || debug {
			gologger.Warning().Msgf("Version check failed: %v", err)
		}
		return
	}

	description := updateutils.GetVersionDescription(Version, latestVersion)
	if description != "" {
		gologger.Info().Msgf("Update status: %s", description)

		// If there's a newer version available, provide helpful information
		if latestVersion != Version {
			gologger.Info().Msg("To update vulnx, use:")
			gologger.Info().Msg("vulnx --update  or  vulnx update")
			gologger.Info().Msg("Or install via pdtm: pdtm -u vulnx")
		}
	}
}

func init() {
	versionCmd.Flags().BoolVar(&disableUpdateCheck, "disable-update-check", false, "disable automatic update check")
	rootCmd.AddCommand(versionCmd)
}
