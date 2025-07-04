package testutils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/projectdiscovery/gologger"
)

// RunCvemapßBinaryAndGetResults returns a list of the results
func RunCvemapBinaryAndGetResults(cvemapBinary string, debug bool, args []string) ([]string, error) {
	cmd := exec.Command("bash", "-c")
	cmdLine := fmt.Sprintf(`./%s `, cvemapBinary)
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

// TestCase is a single integration test case
type TestCase interface {
	// Execute executes a test case and returns any errors if occurred
	Execute() error
}
