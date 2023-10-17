package main

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
