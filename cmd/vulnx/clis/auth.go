package clis

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/projectdiscovery/vulnx/pkg/tools/filters"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	authCmd = &cobra.Command{
		Use:   "auth",
		Short: "configure projectdiscovery cloud platform api key (required)",
		Long: `Configure ProjectDiscovery Cloud Platform API key for vulnx.

This command allows you to interactively set up your PDCP API key. API
authentication is required for all vulnx commands.

You can get your free API key by signing up at https://cloud.projectdiscovery.io
`,
		Example: `
# Configure API key interactively
vulnx auth

# Configure API key non-interactively (for automation)
vulnx auth --api-key YOUR_API_KEY

# Test current API key
vulnx auth --test
`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Override the root command's PersistentPreRunE to avoid client initialization
			if !silent {
				showBanner()
			}
			return nil // Don't initialize client for auth command
		},
		Run: func(cmd *cobra.Command, args []string) {
			runAuthCommand()
		},
	}

	// Auth command flags
	nonInteractiveAPIKey string
	testCurrentKey       bool
)

func runAuthCommand() {
	// Handle non-interactive mode
	if nonInteractiveAPIKey != "" {
		gologger.Info().Msg("Running in non-interactive mode...")

		// Validate the API key format (basic validation)
		if len(nonInteractiveAPIKey) < 10 {
			gologger.Fatal().Msg("Invalid API key format")
		}

		// Validate the API key with the server
		gologger.Info().Msg("Validating API key...")

		// Temporarily set the API key in environment for validation
		originalEnvKey := os.Getenv("PDCP_API_KEY")
		os.Setenv("PDCP_API_KEY", nonInteractiveAPIKey)
		defer func() {
			if originalEnvKey != "" {
				os.Setenv("PDCP_API_KEY", originalEnvKey)
			} else {
				os.Unsetenv("PDCP_API_KEY")
			}
		}()

		// Validate the API key with the server
		if !validateCurrentAPIKey(nonInteractiveAPIKey, "provided API key") {
			gologger.Fatal().Msg("API key validation failed")
		}

		// Key is valid, now save it
		ph := pdcp.PDCPCredHandler{}
		creds := &pdcp.PDCPCredentials{
			APIKey:   nonInteractiveAPIKey,
			Username: "user", // Placeholder username
		}

		// Save the credentials
		err := ph.SaveCreds(creds)
		if err != nil {
			gologger.Fatal().Msgf("Failed to save credentials: %s", err)
		}

		gologger.Info().Msg("✓ API key validated successfully")
		gologger.Info().Msg("✓ API key saved to credential store")

		// Provide guidance based on environment variable presence
		if originalEnvKey != "" {
			fmt.Println()
			gologger.Warning().Msg("⚠ Important: Environment variable PDCP_API_KEY is still set")
			gologger.Info().Msg("  Current priority: Environment variable > Credential store")
			gologger.Info().Msg("  To use the new key: unset PDCP_API_KEY")
			gologger.Info().Msg("  Or export PDCP_API_KEY with your new key")
		}
		return
	}

	// Handle test-only mode
	if testCurrentKey {
		gologger.Info().Msg("Testing current API key...")

		ph := pdcp.PDCPCredHandler{}
		envApiKey := os.Getenv("PDCP_API_KEY")

		if envApiKey != "" {
			if validateCurrentAPIKey(envApiKey, "environment variable") {
				gologger.Info().Msg("✓ Environment variable API key is working correctly")
			} else {
				gologger.Fatal().Msg("✗ Environment variable API key validation failed")
			}
		} else {
			storedCreds, err := ph.GetCreds()
			if err == nil && storedCreds.APIKey != "" {
				if validateCurrentAPIKey(storedCreds.APIKey, "stored credentials") {
					gologger.Info().Msg("✓ Stored API key is working correctly")
				} else {
					gologger.Fatal().Msg("✗ Stored API key validation failed")
				}
			} else {
				gologger.Fatal().Msg("✗ No API key found to test")
			}
		}
		return
	}

	// Interactive mode (existing logic)
	// Check current authentication status
	ph := pdcp.PDCPCredHandler{}
	envApiKey := os.Getenv("PDCP_API_KEY")
	storedCreds, err := ph.GetCreds()

	// Display current status and provide options
	if envApiKey != "" {
		gologger.Info().Msgf("✓ API key found in environment variable PDCP_API_KEY")
		if len(envApiKey) > 12 {
			gologger.Info().Msgf("  Key: %s...%s (ENV)", envApiKey[:8], envApiKey[len(envApiKey)-4:])
		} else {
			gologger.Info().Msgf("  Key: %s (ENV)", strings.Repeat("*", len(envApiKey)))
		}

		fmt.Println("\nWhat would you like to do?")
		fmt.Println("  1) Test current API key")
		fmt.Println("  2) Configure new API key (save to credential store)")
		fmt.Println("  3) Cancel")
		fmt.Print("\nChoice (1-3): ")

		var choice string
		if _, err := fmt.Scanln(&choice); err != nil {
			gologger.Error().Msgf("Error reading input: %s", err)
			return
		}

		switch strings.TrimSpace(choice) {
		case "1":
			if validateCurrentAPIKey(envApiKey, "environment variable") {
				gologger.Info().Msg("✓ Environment variable API key is valid and working correctly")
				gologger.Info().Msg("No action needed - your authentication is properly configured")
				return
			}
			// If validation fails, ask if they want to configure a new one
			fmt.Print("\nWould you like to configure a new API key? (y/N): ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				gologger.Error().Msgf("Error reading input: %s", err)
				return
			}
			if strings.ToLower(strings.TrimSpace(response)) != "y" {
				gologger.Info().Msg("Authentication setup cancelled")
				return
			}
		case "2":
			gologger.Warning().Msg("Note: New API key will be saved to credential store but environment variable takes precedence")
			gologger.Info().Msg("To use the new key, you'll need to: unset PDCP_API_KEY")
		case "3", "":
			gologger.Info().Msg("Authentication setup cancelled")
			return
		default:
			gologger.Error().Msg("Invalid choice. Please run the command again.")
			return
		}

	} else if err == nil && storedCreds.APIKey != "" {
		gologger.Info().Msgf("✓ Stored API key found for user: %s", storedCreds.Username)
		if len(storedCreds.APIKey) > 12 {
			gologger.Info().Msgf("  Key: %s...%s (CONFIG)", storedCreds.APIKey[:8], storedCreds.APIKey[len(storedCreds.APIKey)-4:])
		} else {
			gologger.Info().Msgf("  Key: %s (CONFIG)", strings.Repeat("*", len(storedCreds.APIKey)))
		}

		fmt.Println("\nWhat would you like to do?")
		fmt.Println("  1) Test current API key")
		fmt.Println("  2) Update API key")
		fmt.Println("  3) Cancel")
		fmt.Print("\nChoice (1-3): ")

		var choice string
		if _, err := fmt.Scanln(&choice); err != nil {
			gologger.Error().Msgf("Error reading input: %s", err)
			return
		}

		switch strings.TrimSpace(choice) {
		case "1":
			if validateCurrentAPIKey(storedCreds.APIKey, "stored credentials") {
				gologger.Info().Msg("✓ Stored API key is valid and working correctly")
				gologger.Info().Msg("No action needed - your authentication is properly configured")
				return
			}
			// If validation fails, ask if they want to update
			fmt.Print("\nWould you like to update your API key? (y/N): ")
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				gologger.Error().Msgf("Error reading input: %s", err)
				return
			}
			if strings.ToLower(strings.TrimSpace(response)) != "y" {
				gologger.Info().Msg("Authentication setup cancelled")
				return
			}
		case "2":
			// Continue to new API key setup
		case "3", "":
			gologger.Info().Msg("Authentication setup cancelled")
			return
		default:
			gologger.Error().Msg("Invalid choice. Please run the command again.")
			return
		}

	} else {
		gologger.Info().Msg("No API key found - setting up new authentication")
	}

	fmt.Println()
	gologger.Info().Msg("Get your free API key by signing up at https://cloud.projectdiscovery.io")

	// Prompt for API key with masked input
	fmt.Print("[*] Enter PDCP API Key (Ctrl+C to abort): ")

	// Mask the API key input for security
	apiKeyBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		gologger.Fatal().Msgf("Error reading input: %s", err)
	}
	fmt.Println() // Add newline since ReadPassword doesn't

	apiKey := strings.TrimSpace(string(apiKeyBytes))
	if apiKey == "" {
		gologger.Info().Msg("Authentication setup aborted")
		return
	}

	// Validate the API key format (basic validation)
	if len(apiKey) < 10 {
		gologger.Fatal().Msg("Invalid API key format")
	}

	// Validate the API key with the server
	gologger.Info().Msg("Validating API key...")

	// Temporarily set the API key in environment for validation
	originalEnvKey := os.Getenv("PDCP_API_KEY")
	os.Setenv("PDCP_API_KEY", apiKey)
	defer func() {
		if originalEnvKey != "" {
			os.Setenv("PDCP_API_KEY", originalEnvKey)
		} else {
			os.Unsetenv("PDCP_API_KEY")
		}
	}()

	// Initialize the vulnx client to test the API key
	err = ensureVulnxClientInitialized(nil)
	if err != nil {
		gologger.Fatal().Msgf("Failed to initialize API client: %s", err)
	}

	// Make a real API call to validate the key
	handler := filters.NewHandler(vulnxClient)
	_, err = handler.List()
	if err != nil {
		gologger.Fatal().Msgf("API key validation failed: %s", err)
	}

	// Key is valid, now save it using the simplified approach
	creds := &pdcp.PDCPCredentials{
		APIKey:   apiKey,
		Username: "user", // We don't have username from the new API, use placeholder
	}

	// Save the credentials
	err = ph.SaveCreds(creds)
	if err != nil {
		gologger.Fatal().Msgf("Failed to save credentials: %s", err)
	}

	gologger.Info().Msg("✓ API key validated successfully")
	gologger.Info().Msg("✓ API key saved to credential store")

	// Provide guidance based on environment variable presence
	if envApiKey != "" {
		fmt.Println()
		gologger.Warning().Msg("⚠ Important: Environment variable PDCP_API_KEY is still set")
		gologger.Info().Msg("  Current priority: Environment variable > Credential store")
		gologger.Info().Msg("  To use the new key: unset PDCP_API_KEY")
		gologger.Info().Msg("  Or export PDCP_API_KEY with your new key")
	}
}

// validateCurrentAPIKey tests if the current API key is valid
func validateCurrentAPIKey(apiKey, source string) bool {
	gologger.Info().Msgf("Testing API key from %s...", source)

	// Temporarily set the API key in environment if it's not already set
	originalEnvKey := os.Getenv("PDCP_API_KEY")
	if originalEnvKey == "" {
		os.Setenv("PDCP_API_KEY", apiKey)
		defer os.Unsetenv("PDCP_API_KEY")
	}

	// Initialize the vulnx client (same method as healthcheck)
	err := ensureVulnxClientInitialized(nil)
	if err != nil {
		gologger.Error().Msgf("✗ Failed to initialize API client: %s", err)
		return false
	}

	if vulnxClient == nil {
		gologger.Error().Msg("✗ API client is nil after initialization")
		return false
	}

	// Make a real API call to test the key (same as healthcheck)
	handler := filters.NewHandler(vulnxClient)
	_, err = handler.List()
	if err != nil {
		gologger.Error().Msgf("✗ API key validation failed: %s", err)
		gologger.Warning().Msg("Your current API key appears to be invalid or expired")
		return false
	}

	return true
}

func init() {
	authCmd.Flags().StringVar(&nonInteractiveAPIKey, "api-key", "", "api key for non-interactive configuration")
	authCmd.Flags().BoolVar(&testCurrentKey, "test", false, "test current api key configuration")
	rootCmd.AddCommand(authCmd)
}
