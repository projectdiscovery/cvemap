package clis

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
)

var (
	completionCmd = &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "generate completion script for your shell",
		Long: `Generate completion script for your shell.

This command generates shell completion scripts for vulnx. The completion script
allows you to use TAB completion for commands, flags, and arguments.

The bash completion script is self-contained and doesn't require the bash-completion
package to be installed.

To load completions:

Bash:
  # Load completion for current session
  source <(vulnx completion bash --silent)

  # Install completion system-wide (requires sudo)
  vulnx completion bash --install

  # Install completion for current user
  vulnx completion bash --install --user

Zsh:
  # Load completion for current session
  source <(vulnx completion zsh)

  # Install completion system-wide
  vulnx completion zsh --install

Fish:
  # Load completion for current session
  vulnx completion fish | source

  # Install completion for current user
  vulnx completion fish --install

PowerShell:
  # Load completion for current session
  vulnx completion powershell | Out-String | Invoke-Expression

  # Install completion for current user
  vulnx completion powershell --install
`,
		Example: `
# Generate bash completion script
vulnx completion bash

# Install bash completion system-wide (requires sudo)
vulnx completion bash --install

# Install bash completion for current user only
vulnx completion bash --install --user

# Generate and save to file
vulnx completion bash > vulnx-completion.bash
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Override parent's PersistentPreRunE to avoid client initialization
			// Completion doesn't need API client
			if !silent {
				showBanner()
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			shell := args[0]
			install, _ := cmd.Flags().GetBool("install")
			userOnly, _ := cmd.Flags().GetBool("user")

			if install {
				if err := installCompletion(shell, userOnly); err != nil {
					gologger.Fatal().Msgf("Failed to install completion: %s", err)
				}
				return
			}

			// Generate completion script
			if err := generateCompletion(shell); err != nil {
				gologger.Fatal().Msgf("Failed to generate completion: %s", err)
			}
		},
	}
)

func generateCompletion(shell string) error {
	switch shell {
	case "bash":
		return generateBashCompletionRobust(os.Stdout)
	case "zsh":
		return rootCmd.GenZshCompletion(os.Stdout)
	case "fish":
		return rootCmd.GenFishCompletion(os.Stdout, true)
	case "powershell":
		return rootCmd.GenPowerShellCompletion(os.Stdout)
	default:
		return fmt.Errorf("unsupported shell: %s", shell)
	}
}

// generateBashCompletionRobust generates a bash completion script that works
// without requiring the bash-completion package
func generateBashCompletionRobust(out *os.File) error {
	// Generate a simple but robust completion script that doesn't depend on bash-completion
	script := `# vulnx bash completion script
_vulnx_completion() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Available commands
    commands="analyze auth completion healthcheck id mcp search version help"
    
    # Available shells for completion command
    shells="bash zsh fish powershell"
    
    # Global flags (available for all commands)
    global_flags="--help --debug --verbose --json --output --silent --no-color --proxy --timeout --debug-req --debug-resp"
    
    case "${prev}" in
        vulnx)
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "${shells}" -- ${cur}) )
            return 0
            ;;
        analyze)
            COMPREPLY=( $(compgen -W "--fields -f --query -q --facet-size ${global_flags}" -- ${cur}) )
            return 0
            ;;
        search)
            COMPREPLY=( $(compgen -W "--limit -n --offset --sort-asc --sort-desc --fields --term-facets --range-facets --highlight --facet-size --product -p --vendor --exclude-product --exclude-vendor --severity -s --exclude-severity --cpe -c --assignee -a --vstatus --vuln-age --product-file --vendor-file --exclude-product-file --exclude-vendor-file --severity-file --exclude-severity-file --assignee-file --kev-only --template -t --poc --hackerone --remote-exploit ${global_flags}" -- ${cur}) )
            return 0
            ;;
        id)
            COMPREPLY=( $(compgen -W "--file ${global_flags}" -- ${cur}) )
            return 0
            ;;
        auth)
            COMPREPLY=( $(compgen -W "--api-key --test ${global_flags}" -- ${cur}) )
            return 0
            ;;
        healthcheck|health|hc)
            COMPREPLY=( $(compgen -W "${global_flags}" -- ${cur}) )
            return 0
            ;;
        mcp)
            COMPREPLY=( $(compgen -W "--mode --port ${global_flags}" -- ${cur}) )
            return 0
            ;;
        version)
            COMPREPLY=( $(compgen -W "--disable-update-check ${global_flags}" -- ${cur}) )
            return 0
            ;;
        --*)
            # Don't complete after flags
            return 0
            ;;
        *)
            # Default to global flags
            COMPREPLY=( $(compgen -W "${global_flags}" -- ${cur}) )
            return 0
            ;;
    esac
}

complete -F _vulnx_completion vulnx
`

	_, err := out.WriteString(script)
	return err
}

func installCompletion(shell string, userOnly bool) error {
	switch shell {
	case "bash":
		return installBashCompletion(userOnly)
	case "zsh":
		return installZshCompletion(userOnly)
	case "fish":
		return installFishCompletion(userOnly)
	case "powershell":
		return installPowerShellCompletion(userOnly)
	default:
		return fmt.Errorf("unsupported shell: %s", shell)
	}
}

func installBashCompletion(userOnly bool) error {
	// Determine installation directory
	var completionDir string
	if userOnly {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		completionDir = filepath.Join(homeDir, ".bash_completion.d")
	} else {
		// Try common system-wide locations
		possibleDirs := []string{
			"/usr/share/bash-completion/completions",
			"/etc/bash_completion.d",
			"/usr/local/share/bash-completion/completions",
			"/usr/local/etc/bash_completion.d",
		}

		for _, dir := range possibleDirs {
			if _, err := os.Stat(dir); err == nil {
				completionDir = dir
				break
			}
		}

		if completionDir == "" {
			return fmt.Errorf("no system bash completion directory found. Use --user flag to install for current user")
		}
	}

	// Create completion directory if it doesn't exist
	if err := os.MkdirAll(completionDir, 0755); err != nil {
		return fmt.Errorf("failed to create completion directory: %w", err)
	}

	completionFile := filepath.Join(completionDir, "vulnx")

	// Check if completion file already exists
	if _, err := os.Stat(completionFile); err == nil {
		if !confirmOverwrite(completionFile) {
			gologger.Info().Msg("Installation cancelled by user")
			return nil
		}
	}

	// Create completion file
	file, err := os.Create(completionFile)
	if err != nil {
		return fmt.Errorf("failed to create completion file: %w", err)
	}
	defer file.Close()

	// Generate completion script
	if err := generateBashCompletionRobust(file); err != nil {
		return fmt.Errorf("failed to generate bash completion: %w", err)
	}

	gologger.Info().Msgf("✅ Bash completion installed successfully at: %s", completionFile)

	if userOnly {
		bashrcPath := filepath.Join(os.Getenv("HOME"), ".bashrc")
		gologger.Info().Msgf("To load completions automatically, add this to your %s:", bashrcPath)
		gologger.Info().Msgf("  source %s", completionFile)
	} else {
		gologger.Info().Msg("Bash completion is now available system-wide.")
		gologger.Info().Msg("You may need to restart your shell or run 'source ~/.bashrc' to activate it.")
	}

	return nil
}

func installZshCompletion(userOnly bool) error {
	var completionDir string
	if userOnly {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		completionDir = filepath.Join(homeDir, ".zsh", "completions")
	} else {
		// Try common system-wide zsh completion directories
		possibleDirs := []string{
			"/usr/share/zsh/site-functions",
			"/usr/local/share/zsh/site-functions",
			"/usr/share/zsh/functions/Completion",
		}

		for _, dir := range possibleDirs {
			if _, err := os.Stat(dir); err == nil {
				completionDir = dir
				break
			}
		}

		if completionDir == "" {
			return fmt.Errorf("no system zsh completion directory found. Use --user flag to install for current user")
		}
	}

	// Create completion directory if it doesn't exist
	if err := os.MkdirAll(completionDir, 0755); err != nil {
		return fmt.Errorf("failed to create completion directory: %w", err)
	}

	completionFile := filepath.Join(completionDir, "_vulnx")

	// Check if completion file already exists
	if _, err := os.Stat(completionFile); err == nil {
		if !confirmOverwrite(completionFile) {
			gologger.Info().Msg("Installation cancelled by user")
			return nil
		}
	}

	// Create completion file
	file, err := os.Create(completionFile)
	if err != nil {
		return fmt.Errorf("failed to create completion file: %w", err)
	}
	defer file.Close()

	// Generate completion script
	if err := rootCmd.GenZshCompletion(file); err != nil {
		return fmt.Errorf("failed to generate zsh completion: %w", err)
	}

	gologger.Info().Msgf("✅ Zsh completion installed successfully at: %s", completionFile)

	if userOnly {
		gologger.Info().Msg("To load completions automatically, add this to your ~/.zshrc:")
		gologger.Info().Msgf("  fpath=(%s $fpath)", completionDir)
		gologger.Info().Msg("  autoload -U compinit && compinit")
	} else {
		gologger.Info().Msg("Zsh completion is now available system-wide.")
		gologger.Info().Msg("You may need to restart your shell or run 'autoload -U compinit && compinit' to activate it.")
	}

	return nil
}

func installFishCompletion(userOnly bool) error {
	var completionDir string
	if userOnly {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		completionDir = filepath.Join(homeDir, ".config", "fish", "completions")
	} else {
		// Try common system-wide fish completion directories
		possibleDirs := []string{
			"/usr/share/fish/completions",
			"/usr/local/share/fish/completions",
		}

		for _, dir := range possibleDirs {
			if _, err := os.Stat(dir); err == nil {
				completionDir = dir
				break
			}
		}

		if completionDir == "" {
			return fmt.Errorf("no system fish completion directory found. Use --user flag to install for current user")
		}
	}

	// Create completion directory if it doesn't exist
	if err := os.MkdirAll(completionDir, 0755); err != nil {
		return fmt.Errorf("failed to create completion directory: %w", err)
	}

	completionFile := filepath.Join(completionDir, "vulnx.fish")

	// Check if completion file already exists
	if _, err := os.Stat(completionFile); err == nil {
		if !confirmOverwrite(completionFile) {
			gologger.Info().Msg("Installation cancelled by user")
			return nil
		}
	}

	// Create completion file
	file, err := os.Create(completionFile)
	if err != nil {
		return fmt.Errorf("failed to create completion file: %w", err)
	}
	defer file.Close()

	// Generate completion script
	if err := rootCmd.GenFishCompletion(file, true); err != nil {
		return fmt.Errorf("failed to generate fish completion: %w", err)
	}

	gologger.Info().Msgf("✅ Fish completion installed successfully at: %s", completionFile)
	gologger.Info().Msg("Fish completion is now available.")
	gologger.Info().Msg("You may need to restart your shell to activate it.")

	return nil
}

func installPowerShellCompletion(userOnly bool) error {
	// PowerShell completion is typically user-specific
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	// Determine PowerShell profile path
	var profilePath string
	if isWindows() {
		profilePath = filepath.Join(homeDir, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")
	} else {
		profilePath = filepath.Join(homeDir, ".config", "powershell", "Microsoft.PowerShell_profile.ps1")
	}

	// Create profile directory if it doesn't exist
	profileDir := filepath.Dir(profilePath)
	if err := os.MkdirAll(profileDir, 0755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	// Generate completion script to a temporary file
	tempFile, err := os.CreateTemp("", "vulnx-completion-*.ps1")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	if err := rootCmd.GenPowerShellCompletion(tempFile); err != nil {
		return fmt.Errorf("failed to generate PowerShell completion: %w", err)
	}

	// Read the generated completion script
	if _, err := tempFile.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek temp file: %w", err)
	}
	completionScript, err := os.ReadFile(tempFile.Name())
	if err != nil {
		return fmt.Errorf("failed to read completion script: %w", err)
	}

	// Check if profile already has vulnx completion
	if _, err := os.Stat(profilePath); err == nil {
		content, err := os.ReadFile(profilePath)
		if err == nil && strings.Contains(string(content), "vulnx completion") {
			if !confirmOverwrite(profilePath) {
				gologger.Info().Msg("Installation cancelled by user")
				return nil
			}
		}
	}

	// Append completion script to profile
	file, err := os.OpenFile(profilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open profile file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString("\n# vulnx completion\n"); err != nil {
		return fmt.Errorf("failed to write completion header: %w", err)
	}

	if _, err := file.Write(completionScript); err != nil {
		return fmt.Errorf("failed to write completion script: %w", err)
	}

	gologger.Info().Msgf("✅ PowerShell completion installed successfully at: %s", profilePath)
	gologger.Info().Msg("PowerShell completion is now available.")
	gologger.Info().Msg("You may need to restart your PowerShell session to activate it.")

	return nil
}

func confirmOverwrite(path string) bool {
	fmt.Printf("Completion file already exists at %s. Overwrite? (y/N): ", path)

	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		response := strings.ToLower(strings.TrimSpace(scanner.Text()))
		return response == "y" || response == "yes"
	}

	return false
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}

func init() {
	completionCmd.Flags().Bool("install", false, "install completion script to system/user completion directory")
	completionCmd.Flags().Bool("user", false, "install completion for current user only (works with --install)")
	rootCmd.AddCommand(completionCmd)
}
