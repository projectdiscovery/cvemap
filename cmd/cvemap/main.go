package main

import "github.com/projectdiscovery/cvemap/runner"

func main() {
	options := runner.ParseOptions()
	runner.Run(*options)
}
