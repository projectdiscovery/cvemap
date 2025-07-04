package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

// VulnshTestCase represents a test case for vulnsh
type VulnshTestCase struct {
	Name        string
	Args        []string
	ExpectedOut string
	ShouldFail  bool
}

func (v *VulnshTestCase) Execute() error {
	output, err := runVulnshBinaryAndGetResults(*currentVulnshBinary, debug, v.Args)
	if err != nil && !v.ShouldFail {
		return errors.Wrapf(err, "vulnsh test '%s' failed unexpectedly", v.Name)
	}
	
	if err == nil && v.ShouldFail {
		return errors.Errorf("vulnsh test '%s' should have failed but succeeded", v.Name)
	}
	
	if v.ExpectedOut != "" {
		outputStr := strings.Join(output, " ")
		if !strings.Contains(outputStr, v.ExpectedOut) {
			return errors.Errorf("vulnsh test '%s' output doesn't contain expected string '%s'. Got: %s", 
				v.Name, v.ExpectedOut, outputStr)
		}
	}
	
	return nil
}

// runVulnshBinaryAndGetResults executes vulnsh with given arguments and returns output
func runVulnshBinaryAndGetResults(vulnshBinary string, debug bool, args []string) ([]string, error) {
	cmd := exec.Command("bash", "-c")
	cmdLine := fmt.Sprintf(`./%s `, vulnshBinary)
	cmdLine += strings.Join(args, " ")
	if debug {
		os.Setenv("DEBUG", "1")
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

// Vulnsh specific test cases
var vulnshTestCases = map[string]*VulnshTestCase{
	"Get By CVE ID": {
		Name:        "Get By CVE ID",
		Args:        []string{"id", "CVE-1999-0027", "--json", "--silent"},
		ExpectedOut: `"cve_id": "CVE-1999-0027"`,
	},
	"Search Command": {
		Name:        "Search Command",
		Args:        []string{"search", "--json", "--silent", "--limit", "1", "severity:critical"},
		ExpectedOut: `"vulnerabilities"`,
	},
	"Version Command": {
		Name:        "Version Command", 
		Args:        []string{"version", "--disable-update-check", "--silent"},
		ExpectedOut: "vulnsh version",
	},
	"Health Check": {
		Name:        "Health Check",
		Args:        []string{"healthcheck", "--silent"},
		ExpectedOut: "Health Check Results",
	},
	"Help Command": {
		Name:        "Help Command",
		Args:        []string{"--help"},
		ExpectedOut: "vulnsh — The Swiss Army knife for vulnerability intel",
	},
	"Search Help": {
		Name:        "Search Help",
		Args:        []string{"search", "help", "--silent"},
		ExpectedOut: "SEARCH COMMAND — OVERVIEW",
	},
	"Groupby Command": {
		Name:        "Groupby Command",
		Args:        []string{"groupby", "--fields", "severity", "--json", "--silent"},
		ExpectedOut: "facets",
	},
}