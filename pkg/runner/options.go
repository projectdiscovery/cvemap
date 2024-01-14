package runner

import "github.com/projectdiscovery/goflags"

type Options struct {
	PdcpAuth  bool
	CveIds    goflags.StringSlice
	CweIds    goflags.StringSlice
	Vendor    goflags.StringSlice
	Product   goflags.StringSlice
	Eproduct  goflags.StringSlice
	Severity  goflags.StringSlice
	CvssScore goflags.StringSlice
	//cvssMetrics        goflags.StringSlice
	EpssPercentile goflags.StringSlice
	//year               goflags.StringSlice
	Assignees goflags.StringSlice
	Reference goflags.StringSlice
	//vulnType           goflags.StringSlice
	IncludeColumns []string
	ExcludeColumns []string
	TableHeaders   []string
	ListId         bool
	EpssScore      string
	Cpe            string
	VulnStatus     string
	Age            string
	Kev            string
	//trending           bool
	Hackerone          string
	HasNucleiTemplate  string
	HasPoc             string
	Search             string
	EnablePageKeys     bool
	Json               bool
	Limit              int
	Offset             int
	Version            bool
	DisableUpdateCheck bool
	Silent             bool
	Verbose            bool
}
