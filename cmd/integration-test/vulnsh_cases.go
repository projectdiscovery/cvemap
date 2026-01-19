package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
)

// VulnxTestCase represents a test case for vulnx
type VulnxTestCase struct {
	Name        string
	Args        []string
	ExpectedOut string
	ShouldFail  bool
}

func (v *VulnxTestCase) Execute() error {
	output, err := runVulnxBinaryAndGetResults(*vulnxBinary, debug, v.Args)
	if err != nil && !v.ShouldFail {
		return errors.Wrapf(err, "vulnx test '%s' failed unexpectedly", v.Name)
	}

	if err == nil && v.ShouldFail {
		return errors.Errorf("vulnx test '%s' should have failed but succeeded", v.Name)
	}

	if v.ExpectedOut != "" {
		outputStr := strings.Join(output, " ")
		if !strings.Contains(outputStr, v.ExpectedOut) {
			return errors.Errorf("vulnx test '%s' output doesn't contain expected string '%s'. Got: %s",
				v.Name, v.ExpectedOut, outputStr)
		}
	}

	return nil
}

// runVulnxBinaryAndGetResults executes vulnx with given arguments and returns output
func runVulnxBinaryAndGetResults(vulnxBinary string, debug bool, args []string) ([]string, error) {
	cmd := exec.Command("bash", "-c")
	cmdLine := fmt.Sprintf(`./%s `, vulnxBinary)
	cmdLine += strings.Join(args, " ")
	if debug {
		if err := os.Setenv("DEBUG", "1"); err != nil {
			gologger.Error().Msgf("Failed to set DEBUG env: %s", err)
		}
		cmd.Stderr = os.Stderr
	}
	cmd.Args = append(cmd.Args, cmdLine)
	data, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	parts := []string{}
	items := strings.Split(string(data), "\n")
	for _, i := range items {
		if i != "" {
			parts = append(parts, i)
		}
	}
	return parts, nil
}

// Vulnx specific test cases
var vulnxTestCases = map[string]*VulnxTestCase{
	"Get By CVE ID": {
		Name:        "Get By CVE ID",
		Args:        []string{"id", "CVE-1999-0027", "--json", "--silent"},
		ExpectedOut: `"cve_id":"CVE-1999-0027"`,
	},
	"Search Command": {
		Name:        "Search Command",
		Args:        []string{"search", "--json", "--silent", "--limit", "1", "severity:critical"},
		ExpectedOut: `"results"`,
	},
	"Health Check": {
		Name:        "Health Check",
		Args:        []string{"healthcheck", "--silent"},
		ExpectedOut: "Authentication: PASS",
	},
	"Help Command": {
		Name:        "Help Command",
		Args:        []string{"--help"},
		ExpectedOut: "vulnx — The Swiss Army knife for vulnerability intel",
	},
	"Analyze Command": {
		Name:        "Analyze Command",
		Args:        []string{"analyze", "--fields", "severity", "--json", "--silent"},
		ExpectedOut: "facets",
	},
}
