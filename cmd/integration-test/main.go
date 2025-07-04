package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/cvemap/pkg/testutils"
	"github.com/projectdiscovery/gologger"
)

var (
	xPDCPHeaderTestKey  = "test-67291d9a-0aa6-49b1-b249-2b9d4b45bcea"
	debug               = os.Getenv("DEBUG") == "true"
	success             = aurora.Green("[✓]").String()
	failed              = aurora.Red("[✘]").String()
	currentCvemapBinary = flag.String("current", "", "Current Branch Cvemap Binary")
	currentVulnshBinary = flag.String("vulnsh", "", "Current Branch Vulnsh Binary")
)

func main() {
	flag.Parse()
	SetupMockServer()
	if err := os.Setenv("CVEMAP_API_URL", "http://localhost:8080/api/v1"); err != nil {
		gologger.Error().Msgf("Failed to set CVEMAP_API_URL: %s", err)
	}
	if err := os.Setenv("PDCP_API_KEY", xPDCPHeaderTestKey); err != nil {
		gologger.Error().Msgf("Failed to set PDCP_API_KEY: %s", err)
	}
	if err := runIntegrationTests(); err != nil {
		fmt.Println("Error running integration tests:", err)
	}
}

var testCases = map[string]testutils.TestCase{
	"Get By cve_id": &CveIDTestCase{},
}

type CveIDTestCase struct{}

func (c *CveIDTestCase) Execute() error {
	currentOutput, err := testutils.RunCvemapBinaryAndGetResults(*currentCvemapBinary, debug, []string{"-id", "CVE-1999-0027", "-j", "-silent"})
	if err != nil {
		return errors.Wrap(err, "could not run cvemap test")
	}
	if len(currentOutput) == 0 {
		return errors.New("no output from cvemap")
	}
	if strings.Contains(strings.Join(currentOutput, ""), `"cve_id": "CVE-1999-0027"`) {
		return nil
	}
	return errors.New("cve_id not found in output")
}

func runIntegrationTests() error {
	// Run cvemap tests
	fmt.Println("Running CVEMap integration tests...")
	for testName, testcase := range testCases {
		if err := testcase.Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "%s CVEMap Test \"%s\" failed: %s\n", failed, testName, err)
		} else {
			fmt.Printf("%s CVEMap Test \"%s\" passed!\n", success, testName)
		}
	}

	// Run vulnsh tests if binary is provided
	if currentVulnshBinary != nil && *currentVulnshBinary != "" {
		fmt.Println("\nRunning Vulnsh integration tests...")
		for testName, testcase := range vulnshTestCases {
			if err := testcase.Execute(); err != nil {
				fmt.Fprintf(os.Stderr, "%s Vulnsh Test \"%s\" failed: %s\n", failed, testName, err)
			} else {
				fmt.Printf("%s Vulnsh Test \"%s\" passed!\n", success, testName)
			}
		}
	} else {
		fmt.Println("\nSkipping Vulnsh tests (no binary provided)")
	}

	return nil
}
