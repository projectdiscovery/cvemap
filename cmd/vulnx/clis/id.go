package clis

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/spf13/cobra"

	"github.com/projectdiscovery/cvemap/pkg/tools/id"
	"github.com/projectdiscovery/cvemap/pkg/tools/renderer"
)

var ( //nolint
	// ID command flags
	idFile string

	idCmd = &cobra.Command{
		Use:   "id [vulnID...]",
		Short: "Get vulnerability details by ID",
		Long: `Get vulnerability details by ID.

Supports multiple input methods:
• Command line arguments: vulnx id CVE-2024-1234 CVE-2024-5678
• Command line (comma-separated): vulnx id CVE-2024-1234,CVE-2024-5678
• File input: vulnx id --file ids.txt
• Stdin input: echo "CVE-2024-1234" | vulnx id

Global flags:
  --json     Output raw JSON (for piping, disables CLI output)
  --output   Write output to file in JSON format (error if file exists)
  --no-color Disable colored output (colors are auto-disabled for non-terminal output)
`,
		Example: `
# Get details for a specific vulnerability
vulnx id CVE-2024-1234

# Get details for multiple vulnerabilities
vulnx id CVE-2024-1234 CVE-2024-5678

# Comma-separated IDs
vulnx id CVE-2024-1234,CVE-2024-5678,CVE-2023-9999

# Read IDs from file (one per line or comma-separated)
vulnx id --file ids.txt

# Read from stdin
echo "CVE-2024-1234" | vulnx id
cat ids.txt | vulnx id

# Output as JSON for piping
vulnx id --json CVE-2024-1234

# Write output to a file (JSON)
vulnx id --output vuln.json CVE-2024-1234

# Disable colors
vulnx id --no-color CVE-2024-1234
`,
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			var vulnIDs []string

			// Collect IDs from various sources
			// 1. Command line arguments (including comma-separated)
			for _, arg := range args {
				// Handle comma-separated values in arguments
				if strings.Contains(arg, ",") {
					ids := strings.Split(arg, ",")
					for _, id := range ids {
						id = strings.TrimSpace(id)
						if id != "" {
							vulnIDs = append(vulnIDs, id)
						}
					}
				} else {
					vulnIDs = append(vulnIDs, arg)
				}
			}

			// 2. File input
			if idFile != "" {
				fileIDs, err := readIDsFromFile(idFile)
				if err != nil {
					gologger.Fatal().Msgf("Failed to read IDs from file: %s", err)
				}
				vulnIDs = append(vulnIDs, fileIDs...)
			}

			// 3. Stdin input (if available and no other input provided)
			if len(vulnIDs) == 0 && fileutil.HasStdin() {
				stdinIDs, err := readIDsFromStdin()
				if err != nil {
					gologger.Fatal().Msgf("Failed to read IDs from stdin: %s", err)
				}
				vulnIDs = append(vulnIDs, stdinIDs...)
			}

			// Input validation
			if len(vulnIDs) == 0 {
				gologger.Fatal().Msg("No vulnerability IDs provided. Use command line arguments, --file, or pipe IDs via stdin")
			}

			// Remove duplicates and validate IDs
			vulnIDs = removeDuplicates(vulnIDs)
			for _, vulnID := range vulnIDs {
				if err := validateSingleID(vulnID); err != nil {
					gologger.Fatal().Msgf("Invalid vulnerability ID '%s': %s", vulnID, err)
				}
			}

			if len(vulnIDs) > 100 {
				gologger.Warning().Msgf("Processing %d IDs. Limiting to first 100 for performance.", len(vulnIDs))
				vulnIDs = vulnIDs[:100]
			}

			// Use the global cvemapClient
			handler := id.NewHandler(cvemapClient)

			// Handle JSON output for multiple IDs
			if jsonOutput || outputFile != "" {
				var allVulns []*cvemap.Vulnerability
				for _, vulnID := range vulnIDs {
					vuln, err := handler.Get(vulnID)
					if err != nil {
						if errors.Is(err, cvemap.ErrNotFound) {
							gologger.Warning().Msgf("Vulnerability not found: %s", vulnID)
							continue
						}
						gologger.Error().Msgf("Failed to fetch vulnerability %s: %s", vulnID, err)
						continue
					}
					allVulns = append(allVulns, vuln)
				}

				if len(allVulns) == 0 {
					gologger.Fatal().Msg("No vulnerabilities were successfully retrieved")
				}

				// Marshal single item or array based on input
				var jsonBytes []byte
				var err error
				if len(vulnIDs) == 1 && len(allVulns) == 1 {
					jsonBytes, err = json.MarshalIndent(allVulns[0], "", "  ")
				} else {
					jsonBytes, err = json.MarshalIndent(allVulns, "", "  ")
				}

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
					gologger.Info().Msgf("Wrote %d vulnerability(s) to file: %s", len(allVulns), outputFile)
					return
				}

				// Print to stdout
				if _, err := os.Stdout.Write(jsonBytes); err != nil {
					gologger.Error().Msgf("Failed to write JSON to stdout: %s", err)
				}
				if _, err := os.Stdout.Write([]byte("\n")); err != nil {
					gologger.Error().Msgf("Failed to write newline to stdout: %s", err)
				}
				return
			}

			// CLI output for multiple vulnerabilities
			// Determine color configuration
			var colors *renderer.ColorConfig
			if noColor || !renderer.IsTerminal() {
				colors = renderer.NoColorConfig()
			} else {
				colors = renderer.DefaultColorConfig()
			}

			successCount := 0
			for i, vulnID := range vulnIDs {
				vuln, err := handler.Get(vulnID)
				if err != nil {
					if errors.Is(err, cvemap.ErrNotFound) {
						gologger.Warning().Msgf("Vulnerability not found: %s", vulnID)
						continue
					}
					gologger.Error().Msgf("Failed to fetch vulnerability %s: %s", vulnID, err)
					continue
				}

				// Convert to renderer entry
				entry := renderer.FromVulnerability(vuln)
				if entry == nil {
					gologger.Error().Msgf("Failed to convert vulnerability data for %s", vulnID)
					continue
				}

				// Add separator between multiple results
				if i > 0 && successCount > 0 {
					separator := strings.Repeat("─", 65)
					if colors != nil {
						fmt.Println(colors.ColorResultSeparator(separator))
					} else {
						fmt.Println(separator)
					}
					fmt.Println()
				}

				// Render detailed output
				result := renderer.RenderDetailed(entry, colors)
				fmt.Println(result)
				successCount++
			}

			if successCount == 0 {
				gologger.Fatal().Msg("No vulnerabilities were successfully retrieved")
			} else if successCount < len(vulnIDs) {
				gologger.Info().Msgf("Successfully retrieved %d out of %d vulnerabilities", successCount, len(vulnIDs))
			}
		},
	}
)

// readIDsFromFile reads vulnerability IDs from a file
func readIDsFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil, fmt.Errorf("file is empty")
	}

	var ids []string

	// Try line-by-line first
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Check if line contains commas (comma-separated format)
		if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					ids = append(ids, part)
				}
			}
		} else {
			ids = append(ids, line)
		}
	}

	return ids, nil
}

// readIDsFromStdin reads vulnerability IDs from stdin
func readIDsFromStdin() ([]string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read from stdin: %w", err)
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return nil, fmt.Errorf("no input provided via stdin")
	}

	var ids []string

	// Split by newlines first
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check if line contains commas
		if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					ids = append(ids, part)
				}
			}
		} else {
			ids = append(ids, line)
		}
	}

	return ids, nil
}

// removeDuplicates removes duplicate IDs while preserving order
func removeDuplicates(ids []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}

	return result
}

// validateSingleID performs input validation for a single vulnerability ID
func validateSingleID(vulnID string) error {
	// Basic CVE ID format validation
	if vulnID == "" {
		return fmt.Errorf("vulnerability ID cannot be empty")
	}

	// Check for reasonable length
	if len(vulnID) < 3 || len(vulnID) > 50 {
		return fmt.Errorf("vulnerability ID length must be between 3 and 50 characters")
	}

	return nil
}

func init() {
	idCmd.Flags().StringVar(&idFile, "file", "", "Read vulnerability IDs from file (one per line or comma-separated)")
	rootCmd.AddCommand(idCmd)
}
