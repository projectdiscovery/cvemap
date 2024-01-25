package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/cvemap/pkg/testutils"
)

var (
	xPDCPHeaderTestKey  = "test-67291d9a-0aa6-49b1-b249-2b9d4b45bcea"
	debug               = os.Getenv("DEBUG") == "true"
	success             = aurora.Green("[✓]").String()
	failed              = aurora.Red("[✘]").String()
	currentCvemapBinary = flag.String("current", "", "Current Branch Cvemap Binary")
)

func main() {
	flag.Parse()
	SetupMockServer()
	os.Setenv("CVEMAP_API_URL", "http://localhost:8080/api/v1")
	os.Setenv("PDCP_API_KEY", xPDCPHeaderTestKey)
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

	for testName, testcase := range testCases {
		if err := testcase.Execute(); err != nil {
			fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, testName, err)
		} else {
			fmt.Printf("%s Test \"%s\" passed!\n", success, testName)
		}
	}
	return nil
}
