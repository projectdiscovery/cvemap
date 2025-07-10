package clis

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/spf13/cobra"
)

const (
	// TODO: Update version as needed - this should be set via ldflags during build
	Version = "v1.0.0"
)

var (
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

	// Use cvemap name temporarily until server-side support is added for vulnx
	// TODO: Change "cvemap" to "vulnx" once server-side support is implemented
	latestVersion, err := updateutils.GetToolVersionCallback("cvemap", Version)()
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
			gologger.Info().Msg("To update vulnx, please check the latest release at:")
			gologger.Info().Msg("https://github.com/projectdiscovery/cvemap/releases")
			gologger.Info().Msg("Note: vulnx updates will be included in cvemap releases until separate releases are available")
		}
	}
}

func init() {
	versionCmd.Flags().BoolVar(&disableUpdateCheck, "disable-update-check", false, "disable automatic update check")
	rootCmd.AddCommand(versionCmd)
}
