package main

import (
	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/cvemap/pkg/runner"
)

func main() {
	// update app mode
	cvemap.IsSDK = false

	// parse options and run
	options := runner.ParseOptions()
	runner := runner.New(options)
	runner.Run()
}
