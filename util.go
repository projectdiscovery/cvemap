package main

import (
	"fmt"
	"strings"
)

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

func extractApplicationFromCPE(cpe string) (string, error) {
	// Split the CPE string using ":" as the separator
	cpeParts := strings.Split(cpe, ":")

	// The application part is typically in the 5th position (index 4) in the CPE string
	if len(cpeParts) >= 5 {
		return cpeParts[4], nil
	}
	return "", fmt.Errorf("invalid CPE string format")
}
