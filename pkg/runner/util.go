package runner

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/projectdiscovery/cvemap/pkg/types"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

func DoHealthCheck(opts Options) string {
	var test strings.Builder
	test.WriteString(fmt.Sprintf("Version: %s\n", Version))
	test.WriteString(fmt.Sprintf("Operating System: %s\n", runtime.GOOS))
	test.WriteString(fmt.Sprintf("Architecture: %s\n", runtime.GOARCH))
	test.WriteString(fmt.Sprintf("Go Version: %s\n", runtime.Version()))
	test.WriteString(fmt.Sprintf("Compiler: %s\n", runtime.Compiler))

	var testResult string
	c4, err := net.Dial("tcp4", "cve.projectdiscovery.io:443")
	if err == nil && c4 != nil {
		if err := c4.Close(); err != nil {
			gologger.Error().Msgf("Failed to close c4: %s", err)
		}
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv4 connectivity to cve.projectdiscovery.io:443 => %s\n", testResult))

	u4, err := net.Dial("udp4", "cve.projectdiscovery.io:53")
	if err == nil && u4 != nil {
		if err := u4.Close(); err != nil {
			gologger.Error().Msgf("Failed to close u4: %s", err)
		}
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv4 UDP connectivity to cve.projectdiscovery.io:53 => %s\n", testResult))
	return test.String()
}

func getLatestVersionCVSSScore(cvss types.CvssMetrics) float64 {
	var highestScore float64
	if cvss.Cvss2 != nil {
		highestScore = cvss.Cvss2.Score
	}
	if cvss.Cvss30 != nil {
		highestScore = cvss.Cvss30.Score
	}
	if cvss.Cvss31 != nil {
		highestScore = cvss.Cvss31.Score
	}
	return highestScore
}

func isDefaultRun(opts *Options) bool {
	options := len(opts.CveIds) == 0 && len(opts.CweIds) == 0 && len(opts.Vendor) == 0 && len(opts.Product) == 0 && len(opts.Severity) == 0 && len(opts.CvssScore) == 0 && len(opts.EpssPercentile) == 0 && len(opts.Assignees) == 0 && len(opts.Reference) == 0 && opts.EpssScore == "" && opts.Cpe == "" && opts.VulnStatus == "" && opts.Age == ""
	filters := opts.Kev == "" && opts.Hackerone == "" && opts.HasNucleiTemplate == "" && opts.HasPoc == "" && opts.RemotlyExploitable == "" && opts.Search == ""
	return options && filters && !fileutil.HasStdin()
}

// clearScreen clears the terminal screen
func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	_ = cmd.Run()
}
