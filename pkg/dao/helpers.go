package dao

import "regexp"

var (
	fuzzyRx = regexp.MustCompile(`\A\-f`)
)

// IsFuzzySelector checks if filter is fuzzy or not.
func IsFuzzySelector(s string) bool {
	if s == "" {
		return false
	}
	return fuzzyRx.MatchString(s)
}
