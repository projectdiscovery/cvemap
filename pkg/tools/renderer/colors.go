package renderer

import (
	"fmt"
	"os"
	"strings"
)

// Color constants for ANSI escape codes
const (
	Reset = "\033[0m"
	Bold  = "\033[1m"
	Dim   = "\033[2m"

	// Colors
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Gray    = "\033[90m"

	// Bright colors
	BrightRed     = "\033[91m"
	BrightGreen   = "\033[92m"
	BrightYellow  = "\033[93m"
	BrightBlue    = "\033[94m"
	BrightMagenta = "\033[95m"
	BrightCyan    = "\033[96m"
	BrightWhite   = "\033[97m"
)

// ColorConfig holds color configuration
type ColorConfig struct {
	Enabled bool

	// CVE ID and severity
	CveID    string
	Critical string
	High     string
	Medium   string
	Low      string
	Unknown  string

	// Content elements
	Title     string
	Arrow     string
	Label     string
	Value     string
	Separator string

	// Status indicators
	Success string
	Warning string
	Error   string
	Info    string

	// Numbers and metrics
	Number string
	Metric string

	// Tags
	Tag string

	// Footer
	Footer string
}

// DefaultColorConfig returns a default color configuration
func DefaultColorConfig() *ColorConfig {
	return &ColorConfig{
		Enabled: true,

		// CVE ID and severity colors
		CveID:    Bold + BrightWhite,
		Critical: Bold + BrightRed,
		High:     Bold + Red,
		Medium:   Bold + Yellow,
		Low:      Bold + Green,
		Unknown:  Bold + Gray,

		// Content elements
		Title:     Bold + BrightWhite,
		Arrow:     BrightCyan,
		Label:     Gray,
		Value:     White,
		Separator: Dim + Gray,

		// Status indicators
		Success: BrightGreen,
		Warning: BrightYellow,
		Error:   Red, // Less bright red for ✘ symbols
		Info:    BrightBlue,

		// Numbers and metrics
		Number: BrightYellow,
		Metric: BrightCyan,

		// Tags
		Tag: Magenta,

		// Footer
		Footer: BrightBlue,
	}
}

// NoColorConfig returns a color configuration with no colors
func NoColorConfig() *ColorConfig {
	return &ColorConfig{
		Enabled: false,
	}
}

// IsTerminal checks if output is a terminal
func IsTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

// Colorize applies color to text if colors are enabled
func (c *ColorConfig) Colorize(text, color string) string {
	if !c.Enabled {
		return text
	}
	return color + text + Reset
}

// ColorSeverity colors severity text based on severity level
func (c *ColorConfig) ColorSeverity(severity string) string {
	if !c.Enabled {
		return severity
	}

	switch strings.ToLower(severity) {
	case "critical":
		return c.Colorize(severity, c.Critical)
	case "high":
		return c.Colorize(severity, c.High)
	case "medium":
		return c.Colorize(severity, c.Medium)
	case "low":
		return c.Colorize(severity, c.Low)
	default:
		return c.Colorize(severity, c.Unknown)
	}
}

// ColorCVEID colors CVE ID
func (c *ColorConfig) ColorCVEID(cveID string) string {
	return c.Colorize(cveID, c.CveID)
}

// ColorTitle colors title
func (c *ColorConfig) ColorTitle(title string) string {
	return c.Colorize(title, c.Title)
}

// ColorArrow colors the arrow symbol
func (c *ColorConfig) ColorArrow(arrow string) string {
	return c.Colorize(arrow, c.Arrow)
}

// ColorLabel colors field labels
func (c *ColorConfig) ColorLabel(label string) string {
	return c.Colorize(label, c.Label)
}

// ColorValue colors field values
func (c *ColorConfig) ColorValue(value string) string {
	return c.Colorize(value, c.Value)
}

// ColorSeparator colors separators
func (c *ColorConfig) ColorSeparator(separator string) string {
	return c.Colorize(separator, c.Separator)
}

// ColorResultSeparator colors the separator between results with special styling
func (c *ColorConfig) ColorResultSeparator(separator string) string {
	if !c.Enabled {
		return separator
	}
	return c.Colorize(separator, Dim+Blue)
}

// ColorNumber colors numeric values
func (c *ColorConfig) ColorNumber(number string) string {
	return c.Colorize(number, c.Number)
}

// ColorMetric colors metrics (CVSS, EPSS)
func (c *ColorConfig) ColorMetric(metric string) string {
	return c.Colorize(metric, c.Metric)
}

// ColorTag colors tags
func (c *ColorConfig) ColorTag(tag string) string {
	return c.Colorize(tag, c.Tag)
}

// ColorFooter colors footer text
func (c *ColorConfig) ColorFooter(footer string) string {
	return c.Colorize(footer, c.Footer)
}

// ColorBoolean colors boolean checkmarks
func (c *ColorConfig) ColorBoolean(checkmark string) string {
	if !c.Enabled {
		return checkmark
	}

	if checkmark == "✔" {
		return c.Colorize(checkmark, c.Success)
	} else if checkmark == "✘" {
		return c.Colorize(checkmark, c.Error)
	}
	return checkmark
}

// ColorExposure colors exposure values with appropriate colors
func (c *ColorConfig) ColorExposure(exposure string) string {
	if !c.Enabled {
		return exposure
	}

	if strings.Contains(exposure, "unknown") {
		return c.Colorize(exposure, c.Unknown)
	}

	// High exposure gets warning color
	if strings.Contains(exposure, "K") || strings.Contains(exposure, "M") {
		return c.Colorize(exposure, c.Warning)
	}

	return c.Colorize(exposure, c.Number)
}

// ColorExploitAvailability colors exploit availability with urgency
func (c *ColorConfig) ColorExploitAvailability(available bool, pocCount int, kevStatus bool) string {
	if !c.Enabled {
		if available || pocCount > 0 || kevStatus {
			return "⚠️ EXPLOITS AVAILABLE"
		}
		return "No known exploits"
	}

	if available || pocCount > 0 || kevStatus {
		return c.Colorize("⚠️ EXPLOITS AVAILABLE", Bold+BrightRed)
	}
	return c.Colorize("No known exploits", Dim+Green)
}

// ColorAgeUrgency colors vulnerability age with urgency indicators
func (c *ColorConfig) ColorAgeUrgency(ageInDays int) string {
	ageStr := fmt.Sprintf("%dd", ageInDays)
	if !c.Enabled {
		if ageInDays <= 7 {
			return "🚨 " + ageStr + " (NEW)"
		} else if ageInDays <= 30 {
			return "⚡ " + ageStr + " (RECENT)"
		}
		return ageStr
	}

	if ageInDays <= 7 {
		return c.Colorize("🚨 "+ageStr+" (NEW)", Bold+BrightRed)
	} else if ageInDays <= 30 {
		return c.Colorize("⚡ "+ageStr+" (RECENT)", Bold+BrightYellow)
	}
	return c.Colorize(ageStr, c.Number)
}

// ColorCVSSScore colors CVSS score with severity indicators
func (c *ColorConfig) ColorCVSSScore(score float64) string {
	scoreStr := fmt.Sprintf("%.1f", score)
	if !c.Enabled {
		return scoreStr
	}

	if score >= 9.0 {
		return c.Colorize("🔥 "+scoreStr, Bold+BrightRed)
	} else if score >= 7.0 {
		return c.Colorize("⚠️ "+scoreStr, Bold+Red)
	} else if score >= 4.0 {
		return c.Colorize(scoreStr, Yellow)
	}
	return c.Colorize(scoreStr, Green)
}

// ColorEPSSScore colors EPSS score with probability indicators
func (c *ColorConfig) ColorEPSSScore(score float64) string {
	scoreStr := fmt.Sprintf("%.4f", score)
	if !c.Enabled {
		if score >= 0.7 {
			return scoreStr + " (HIGH PROBABILITY)"
		}
		return scoreStr
	}

	if score >= 0.7 {
		return c.Colorize(scoreStr+" (HIGH PROBABILITY)", Bold+BrightRed)
	} else if score >= 0.4 {
		return c.Colorize(scoreStr+" (MEDIUM PROBABILITY)", Bold+Yellow)
	}
	return c.Colorize(scoreStr, c.Metric)
}

// ColorKEVStatus colors KEV status with high visibility
func (c *ColorConfig) ColorKEVStatus(isKEV bool) string {
	if !c.Enabled {
		if isKEV {
			return "🚨 KEV LISTED"
		}
		return "✘"
	}

	if isKEV {
		return c.Colorize("🚨 KEV LISTED", Bold+BrightRed)
	}
	return c.Colorize("✘", c.Error)
}

// colorPriorityLevels colors priority levels in the text
func (c *ColorConfig) colorPriorityLevels(text string) string {
	if !c.Enabled {
		return text
	}

	// Color priority levels
	text = strings.ReplaceAll(text, "Priority: IMMEDIATE", "Priority: "+c.Colorize("IMMEDIATE", Bold+BrightRed))
	text = strings.ReplaceAll(text, "Priority: URGENT", "Priority: "+c.Colorize("URGENT", Bold+Red))
	text = strings.ReplaceAll(text, "Priority: HIGH", "Priority: "+c.Colorize("HIGH", Bold+Yellow))
	text = strings.ReplaceAll(text, "Priority: MEDIUM", "Priority: "+c.Colorize("MEDIUM", Bold+Yellow))
	text = strings.ReplaceAll(text, "Priority: LOW", "Priority: "+c.Colorize("LOW", Bold+Green))

	// Color exploit status
	text = strings.ReplaceAll(text, "EXPLOITS AVAILABLE", c.Colorize("EXPLOITS AVAILABLE", Bold+BrightYellow))
	text = strings.ReplaceAll(text, "No exploits", c.Colorize("No exploits", Dim+Green))

	// Color KEV status
	text = strings.ReplaceAll(text, "KEV LISTED", c.Colorize("KEV LISTED", Bold+BrightMagenta))

	return text
}

// ColorizeFormattedLine applies colors to a formatted line
func (c *ColorConfig) ColorizeFormattedLine(line string, lineNum int) string {
	if !c.Enabled {
		return line
	}

	// Line 1: CVE ID, severity, and title
	if lineNum == 1 {
		// Pattern: [CVE-ID] Severity - Title
		if strings.Contains(line, "[") && strings.Contains(line, "]") {
			parts := strings.SplitN(line, "] ", 2)
			if len(parts) == 2 {
				cveID := parts[0] + "]"
				rest := parts[1]

				// Color CVE ID
				cveID = c.ColorCVEID(cveID)

				// Split severity and title
				if strings.Contains(rest, " - ") {
					severityTitle := strings.SplitN(rest, " - ", 2)
					if len(severityTitle) == 2 {
						severity := c.ColorSeverity(severityTitle[0])
						title := c.ColorTitle(severityTitle[1])
						return cveID + " " + severity + c.ColorSeparator(" - ") + title
					}
				}

				return cveID + " " + rest
			}
		}
	}

	// Lines 2-6: Detail lines with arrows
	if lineNum >= 2 && lineNum <= 6 {
		// Color the arrow and separators
		result := line
		result = strings.Replace(result, "  ↳ ", c.ColorArrow("  ↳ "), 1)
		result = strings.ReplaceAll(result, " | ", c.ColorSeparator(" | "))
		result = strings.ReplaceAll(result, ": ", c.ColorSeparator(": "))

		// Color specific patterns
		result = c.colorSpecificPatterns(result)

		// Color priority levels
		result = c.colorPriorityLevels(result)

		return result
	}

	return line
}

// colorSpecificPatterns colors specific patterns in the text
func (c *ColorConfig) colorSpecificPatterns(text string) string {
	if !c.Enabled {
		return text
	}

	result := text

	// Color checkmarks
	result = strings.ReplaceAll(result, "✔", c.ColorBoolean("✔"))
	result = strings.ReplaceAll(result, "✘", c.ColorBoolean("✘"))

	// Color numbers (age, POCs, etc.)
	result = c.colorNumbers(result)

	// Color age urgency indicators (NEW, RECENT)
	result = c.colorAgeUrgency(result)

	// Color metrics (CVSS, EPSS)
	result = c.colorMetrics(result)

	// Color exposure values
	result = c.colorExposureValues(result)

	return result
}

// colorNumbers colors numeric values in the text
func (c *ColorConfig) colorNumbers(text string) string {
	// Simple regex-like replacement for common number patterns
	patterns := []string{
		"Age: ", "POCs: ", "Vuln Age: ",
	}

	result := text
	for _, pattern := range patterns {
		if strings.Contains(result, pattern) {
			parts := strings.Split(result, pattern)
			for i := 1; i < len(parts); i++ {
				// Find the number part
				words := strings.Fields(parts[i])
				if len(words) > 0 {
					// Color the first word (should be a number)
					number := words[0]
					colored := c.ColorNumber(number)
					parts[i] = strings.Replace(parts[i], number, colored, 1)
				}
			}
			result = strings.Join(parts, pattern)
		}
	}

	return result
}

// colorAgeUrgency colors age urgency indicators (NEW, RECENT)
func (c *ColorConfig) colorAgeUrgency(text string) string {
	if !c.Enabled {
		return text
	}

	// Color NEW indicator (≤7 days) - bright cyan for freshness
	text = strings.ReplaceAll(text, "(NEW)", c.Colorize("(NEW)", Bold+BrightCyan))

	// Color RECENT indicator (≤30 days) - bright blue for attention
	text = strings.ReplaceAll(text, "(RECENT)", c.Colorize("(RECENT)", Bold+BrightBlue))

	return text
}

// colorMetrics colors CVSS and EPSS values
func (c *ColorConfig) colorMetrics(text string) string {
	patterns := []string{"CVSS: ", "EPSS: "}

	result := text
	for _, pattern := range patterns {
		if strings.Contains(result, pattern) {
			parts := strings.Split(result, pattern)
			for i := 1; i < len(parts); i++ {
				// Find the metric value
				words := strings.Fields(parts[i])
				if len(words) > 0 {
					metric := words[0]
					colored := c.ColorMetric(metric)
					parts[i] = strings.Replace(parts[i], metric, colored, 1)
				}
			}
			result = strings.Join(parts, pattern)
		}
	}

	return result
}

// colorExposureValues colors exposure values
func (c *ColorConfig) colorExposureValues(text string) string {
	if strings.Contains(text, "Exposure: ") {
		parts := strings.Split(text, "Exposure: ")
		for i := 1; i < len(parts); i++ {
			// Find the exposure value
			words := strings.Fields(parts[i])
			if len(words) > 0 {
				exposure := words[0]
				colored := c.ColorExposure(exposure)
				parts[i] = strings.Replace(parts[i], exposure, colored, 1)
			}
		}
		text = strings.Join(parts, "Exposure: ")
	}

	return text
}
