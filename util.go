package main

import fileutil "github.com/projectdiscovery/utils/file"

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
	options := len(opts.cveIds) == 0 && len(opts.cweIds) == 0 && len(opts.vendor) == 0 && len(opts.product) == 0 && len(opts.severity) == 0 && len(opts.cvssScore) == 0 && len(opts.epssPercentile) == 0 && len(opts.assignees) == 0 && len(opts.reference) == 0 && opts.epssScore == "" && opts.cpe == "" && opts.vulnStatus == "" && opts.age == ""
	filters := !opts.kev && !opts.hackerone && !opts.hasNucleiTemplate && !opts.hasPoc
	return options && filters && !fileutil.HasStdin()
}
