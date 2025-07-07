package clis

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/cvemap/pkg/tools/filters"
	"github.com/projectdiscovery/gologger"
	"github.com/spf13/cobra"
)

var (
	healthCmd = &cobra.Command{
		Use:     "healthcheck",
		Aliases: []string{"health", "hc"},
		Short:   "Check vulnsh health and connectivity",
		Long: `Check vulnsh health and connectivity to the ProjectDiscovery API.

This command performs various checks to ensure vulnsh is working correctly:
- API key validation
- Network connectivity
- API endpoint accessibility
- Response time measurement

The health check uses the vulnerability filters endpoint as it's lightweight
and provides good coverage of the API functionality.
`,
		Example: `
# Run health check
vulnsh healthcheck

# Run health check with detailed output
vulnsh healthcheck --verbose

# Short alias
vulnsh hc
`,
		Run: func(cmd *cobra.Command, args []string) {
			if !silent {
				showBanner()
			}
			runHealthCheck()
		},
	}
)

type HealthCheckResult struct {
	Check    string        `json:"check"`
	Status   string        `json:"status"`
	Duration time.Duration `json:"duration,omitempty"`
	Message  string        `json:"message,omitempty"`
	Details  interface{}   `json:"details,omitempty"`
}

func runHealthCheck() {
	gologger.Info().Msg("Running vulnsh health check...")

	var results []HealthCheckResult

	// Check 1: API Key validation
	authResult := checkAuthentication()
	results = append(results, authResult)

	if authResult.Status != "PASS" {
		gologger.Error().Msg("Health check failed: Authentication issues detected")
		displayResults(results)
		return
	}

	// Check 2: API connectivity and response time
	connectivityResult := checkAPIConnectivity()
	results = append(results, connectivityResult)

	// Check 3: API endpoint functionality
	endpointResult := checkAPIEndpoint()
	results = append(results, endpointResult)

	// Display results
	displayResults(results)

	// Overall status
	allPassed := true
	for _, result := range results {
		if result.Status != "PASS" {
			allPassed = false
			break
		}
	}

	if allPassed {
		gologger.Info().Msg("✅ All health checks passed - vulnsh is working correctly")
	} else {
		gologger.Error().Msg("❌ Some health checks failed - see details above")
	}
}

func checkAuthentication() HealthCheckResult {
	start := time.Now()

	// Try to initialize the cvemap client
	err := ensureCvemapClientInitialized(nil)
	duration := time.Since(start)

	if err != nil {
		return HealthCheckResult{
			Check:    "Authentication",
			Status:   "FAIL",
			Duration: duration,
			Message:  fmt.Sprintf("Failed to initialize API client: %v", err),
		}
	}

	if cvemapClient == nil {
		return HealthCheckResult{
			Check:    "Authentication",
			Status:   "FAIL",
			Duration: duration,
			Message:  "API client is nil after initialization",
		}
	}

	return HealthCheckResult{
		Check:    "Authentication",
		Status:   "PASS",
		Duration: duration,
		Message:  "API key configured and client initialized successfully",
	}
}

func checkAPIConnectivity() HealthCheckResult {
	start := time.Now()

	// Try to make a simple API call to test connectivity
	handler := filters.NewHandler(cvemapClient)

	// Measure round-trip time
	_, err := handler.List()
	duration := time.Since(start)

	if err != nil {
		return HealthCheckResult{
			Check:    "API Connectivity",
			Status:   "FAIL",
			Duration: duration,
			Message:  fmt.Sprintf("Failed to connect to API: %v", err),
			Details: map[string]interface{}{
				"error_type": fmt.Sprintf("%T", err),
				"timeout":    "30s",
			},
		}
	}

	// Check if response time is reasonable
	status := "PASS"
	message := fmt.Sprintf("API connectivity successful (response time: %v)", duration)

	if duration > 10*time.Second {
		status = "WARN"
		message = fmt.Sprintf("API connectivity successful but slow (response time: %v)", duration)
	}

	return HealthCheckResult{
		Check:    "API Connectivity",
		Status:   status,
		Duration: duration,
		Message:  message,
		Details: map[string]interface{}{
			"endpoint": "vulnerability filters",
			"timeout":  "30s",
		},
	}
}

func checkAPIEndpoint() HealthCheckResult {
	start := time.Now()

	// Test the filters endpoint functionality
	handler := filters.NewHandler(cvemapClient)
	filters, err := handler.List()
	duration := time.Since(start)

	if err != nil {
		return HealthCheckResult{
			Check:    "API Endpoint",
			Status:   "FAIL",
			Duration: duration,
			Message:  fmt.Sprintf("Filters endpoint failed: %v", err),
		}
	}

	if len(filters) == 0 {
		return HealthCheckResult{
			Check:    "API Endpoint",
			Status:   "WARN",
			Duration: duration,
			Message:  "Filters endpoint returned empty response",
		}
	}

	return HealthCheckResult{
		Check:    "API Endpoint",
		Status:   "PASS",
		Duration: duration,
		Message:  fmt.Sprintf("Filters endpoint working correctly (%d filters available)", len(filters)),
		Details: map[string]interface{}{
			"filters_count": len(filters),
			"sample_fields": getSampleFields(filters, 3),
		},
	}
}

func getSampleFields(filters []cvemap.VulnerabilityFilter, limit int) []string {
	var fields []string
	for i, filter := range filters {
		if i >= limit {
			break
		}
		fields = append(fields, filter.Field)
	}
	return fields
}

func displayResults(results []HealthCheckResult) {
	fmt.Println()
	gologger.Info().Msg("Health Check Results:")
	fmt.Println()

	for _, result := range results {
		status := result.Status
		var statusIcon string

		switch status {
		case "PASS":
			statusIcon = "✅"
		case "FAIL":
			statusIcon = "❌"
		case "WARN":
			statusIcon = "⚠️"
		default:
			statusIcon = "❓"
		}

		fmt.Printf("  %s %s: %s", statusIcon, result.Check, status)
		if result.Duration > 0 {
			fmt.Printf(" (%v)", result.Duration)
		}
		fmt.Println()

		if result.Message != "" {
			fmt.Printf("    %s\n", result.Message)
		}

		if verbose && result.Details != nil {
			detailsBytes, _ := json.MarshalIndent(result.Details, "    ", "  ")
			fmt.Printf("    Details: %s\n", string(detailsBytes))
		}

		fmt.Println()
	}
}

func init() {
	rootCmd.AddCommand(healthCmd)
}
