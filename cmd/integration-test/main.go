package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/vulnx/pkg/testutils"
	"github.com/projectdiscovery/gologger"
)

var (
	xPDCPHeaderTestKey = "test-67291d9a-0aa6-49b1-b249-2b9d4b45bcea"
	debug              = os.Getenv("DEBUG") == "true"
	success            = aurora.Green("[✓]").String()
	failed             = aurora.Red("[✘]").String()
	vulnxBinary        = flag.String("vulnx", "", "Vulnx Binary")
)

func main() {
	flag.Parse()
	SetupMockServer()
	if err := os.Setenv("VULNX_API_URL", "http://localhost:8080/api/v1"); err != nil {
		gologger.Error().Msgf("Failed to set VULNX_API_URL: %s", err)
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
	output, err := testutils.RunVulnxBinaryAndGetResults(*vulnxBinary, debug, []string{"id", "CVE-1999-0027", "--json", "--silent"})
	if err != nil {
		return errors.Wrap(err, "could not run vulnx test")
	}
	if len(output) == 0 {
		return errors.New("no output from vulnx")
	}
	if strings.Contains(strings.Join(output, ""), `"cve_id": "CVE-1999-0027"`) {
		return nil
	}
	return errors.New("cve_id not found in output")
}

func runIntegrationTests() error {
	fmt.Println("Running Vulnx integration tests...")
	for testName, testcase := range testCases {
		if err := testcase.Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "%s Vulnx Test \"%s\" failed: %s\n", failed, testName, err)
		} else {
			fmt.Printf("%s Vulnx Test \"%s\" passed!\n", success, testName)
		}
	}

	for testName, testcase := range vulnxTestCases {
		if err := testcase.Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "%s Vulnx Test \"%s\" failed: %s\n", failed, testName, err)
		} else {
			fmt.Printf("%s Vulnx Test \"%s\" passed!\n", success, testName)
		}
	}

	return nil
}
