package main

import "github.com/projectdiscovery/cvemap/pkg/runner"

func main() {
	options := runner.ParseOptions()
	runner.Run(*options)
}
