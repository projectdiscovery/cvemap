package clis

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/spf13/cobra"
)

var (
	authCmd = &cobra.Command{
		Use:   "auth",
		Short: "Configure ProjectDiscovery Cloud Platform API key",
		Long: `Configure ProjectDiscovery Cloud Platform API key for vulnsh.

This command allows you to interactively set up your PDCP API key, which is required
to access the ProjectDiscovery Vulnerability Database.

You can get your free API key by signing up at https://cloud.projectdiscovery.io
`,
		Example: `
# Configure API key interactively
vulnsh auth

# The command will prompt you to enter your API key
`,
		Run: func(cmd *cobra.Command, args []string) {
			if !silent {
				showBanner()
			}
			runAuthCommand()
		},
	}
)

func runAuthCommand() {
	gologger.Info().Msg("Get your free API key by signing up at https://cloud.projectdiscovery.io")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("[*] Enter PDCP API Key (exit to abort): ")

	apiKey, err := reader.ReadString('\n')
	if err != nil {
		gologger.Fatal().Msgf("Error reading input: %s", err)
	}

	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" || strings.ToLower(apiKey) == "exit" {
		gologger.Info().Msg("Authentication setup aborted")
		return
	}

	// Validate the API key format (basic validation)
	if len(apiKey) < 10 {
		gologger.Fatal().Msg("Invalid API key format")
	}

	// Initialize PDCP handler
	ph := pdcp.PDCPCredHandler{}

	// Validate the API key with the server
	apiServer := "https://cloud.projectdiscovery.io"
	if customServer := os.Getenv("PDCP_API_SERVER"); customServer != "" {
		apiServer = customServer
	}

	gologger.Info().Msg("Validating API key...")

	validatedCreds, err := ph.ValidateAPIKey(apiKey, apiServer, "cvemap")
	if err != nil {
		gologger.Fatal().Msgf("API key validation failed: %s", err)
	}

	// Save the credentials
	err = ph.SaveCreds(validatedCreds)
	if err != nil {
		gologger.Fatal().Msgf("Failed to save credentials: %s", err)
	}

	gologger.Info().Msgf("Successfully logged in as (%s)", validatedCreds.Username)
	gologger.Info().Msg("API key saved successfully")
}

func init() {
	rootCmd.AddCommand(authCmd)
}
