package main

import (
	"log"

	"github.com/projectdiscovery/cvemap/cmd/vulnsh/clis"
)

func main() {
	if err := clis.Execute(); err != nil {
		log.Fatalf("Could not execute CLI: %s", err)
	}
}
