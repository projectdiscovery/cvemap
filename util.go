package main

import (
	"strconv"
	"time"
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

func yearToDatetime(year string) string {
	var y int64
	y, err := strconv.ParseInt(year, 10, 64)
	if err != nil {
		return ""
	}
	// Create a time object representing the start of the year
	startOfYear := time.Date(int(y), 1, 1, 0, 0, 0, 0, time.UTC)
	// Format the time as a string
	return startOfYear.Format("2006-01-02T15:04:05Z")
}
