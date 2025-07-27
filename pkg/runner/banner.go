package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/auth/pdcp"
	updateutils "github.com/projectdiscovery/utils/update"
)

const banner = `

   ______   _____  ____ ___  ____  ____
  / ___/ | / / _ \/ __ \__ \/ __ \/ __ \
 / /__ | |/ /  __/ / / / / / /_/ / /_/ /
 \___/ |___/\___/_/ /_/ /_/\__,_/ .___/
                               /_/

`

// Version is the current version
const Version = `v0.0.7`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	// Show deprecation warning
	gologger.Print().Msgf("⚠️  Important: cvemap uses an older API version that will be discontinued on August 1, 2025.")
	gologger.Info().Msgf("   Please migrate to 'vulnx' for continued access to vulnerability data.")
	gologger.Info().Msgf("   Install: go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest\n")
}

// GetUpdateCallback returns a callback function that updates proxify
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("cvemap", Version)()
	}
}

// AuthWithPDCP is used to authenticate with PDCP
func AuthWithPDCP() {
	showBanner()
	pdcp.CheckNValidateCredentials("cvemap")
}
