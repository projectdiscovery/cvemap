package runner

import (
	"os"
	"os/exec"
	"runtime"

	fileutil "github.com/projectdiscovery/utils/file"
)

func getLatestVersionCVSSScore(cvss CvssMetrics) float64 {
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

func isDefaultRun(opts Options) bool {
	options := len(opts.CveIds) == 0 && len(opts.CweIds) == 0 && len(opts.Vendor) == 0 && len(opts.Product) == 0 && len(opts.Severity) == 0 && len(opts.CvssScore) == 0 && len(opts.EpssPercentile) == 0 && len(opts.Assignees) == 0 && len(opts.Reference) == 0 && opts.EpssScore == "" && opts.Cpe == "" && opts.VulnStatus == "" && opts.Age == ""
	filters := opts.Kev == "" && opts.Hackerone == "" && opts.HasNucleiTemplate == "" && opts.HasPoc == "" && opts.RemotlyExploitable == ""
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
