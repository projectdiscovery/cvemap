package main

import (
	"github.com/projectdiscovery/cvemap/cmd/vulnsh/clis"
	"github.com/projectdiscovery/gologger"
)

func main() {
	if err := clis.Execute(); err != nil {
		gologger.Fatal().Msgf("Could not execute CLI: %s", err)
	}
}
