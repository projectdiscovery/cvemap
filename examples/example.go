package main

import (
	"fmt"
	"github.com/projectdiscovery/cvemap/runner"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)

	options := &runner.Options{
		CveIds: []string{"CVE-2019-0708"},
	}

	cvesResp, err := runner.GetCves(*options)
	if err != nil {
		gologger.Fatal().Msgf("Error getting CVEs: %s\n", err)
	}

	for _, cve := range cvesResp.Cves {
		fmt.Println(cve)
	}
}
