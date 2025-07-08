package renderer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Render generates formatted output for vulnerability entries using the provided layout
func Render(entries []*Entry, layout []LayoutLine, totalResults, shownResults int) string {
	return RenderWithColors(entries, layout, totalResults, shownResults, DefaultColorConfig())
}

// RenderDetailed generates detailed formatted output for a single vulnerability
func RenderDetailed(entry *Entry, colors *ColorConfig) string {
	if entry == nil {
		return ""
	}

	var output strings.Builder

	// Header line
	header := fmt.Sprintf("[%s] %s - %s", entry.DocID, capitalizeFirst(entry.Severity), entry.Name)
	colored := colors.ColorizeFormattedLine(header, 1)
	output.WriteString(colored)
	output.WriteString("\n")

	// Status line
	status := fmt.Sprintf("  ↳ Priority: %s | %s | Vuln Age: %s",
		getResearchPriority(entry), getExploitStatus(entry), formatAgeUrgency(entry.AgeInDays))
	colored = colors.ColorizeFormattedLine(status, 2)
	output.WriteString(colored)
	output.WriteString("\n")

	// Metrics line
	metrics := fmt.Sprintf("  ↳ CVSS: %s | EPSS: %s | KEV: %s",
		formatCVSSEnhanced(entry.CvssScore), formatEPSSEnhanced(entry.EpssScore), formatKEVEnhanced(entry))
	colored = colors.ColorizeFormattedLine(metrics, 3)
	output.WriteString(colored)
	output.WriteString("\n")

	// Patch & Tools line
	tools := fmt.Sprintf("  ↳ Patch: %s | POCs: %s | Template: %s | HackerOne: %s",
		formatBoolCheckmark(entry.IsPatchAvailable), formatPocCount(entry.PocCount),
		formatBoolCheckmark(entry.IsTemplate), formatBoolCheckmark(entry.H1 != nil && entry.H1.Reports > 0))
	colored = colors.ColorizeFormattedLine(tools, 4)
	output.WriteString(colored)
	output.WriteString("\n")

	// Add detailed sections with proper spacing and icons
	sectionsAdded := false

	// Summary section (formerly Description)
	if entry.Description != "" {
		descLines := formatMultilineText(entry.Description)
		if len(descLines) > 0 {
			// Add line break before first detailed section
			output.WriteString("\n")
			sectionsAdded = true

			// Header without ↳
			header := "Summary 📝"
			colored = colors.ColorizeFormattedLine(header, 5)
			output.WriteString(colored)
			output.WriteString("\n")

			// Content with ↳ on first line
			firstLine := fmt.Sprintf("  ↳ %s", descLines[0])
			colored = colors.ColorizeFormattedLine(firstLine, 6)
			output.WriteString(colored)
			output.WriteString("\n")

			// Continuation lines with proper indentation
			for i := 1; i < len(descLines); i++ {
				continuationLine := fmt.Sprintf("    %s", descLines[i])
				colored = colors.ColorizeFormattedLine(continuationLine, 6)
				output.WriteString(colored)
				output.WriteString("\n")
			}
		}
	}

	// Risk section (formerly Impact)
	if entry.Impact != "" {
		impactLines := formatMultilineText(entry.Impact)
		if len(impactLines) > 0 {
			if sectionsAdded {
				output.WriteString("\n")
			}
			sectionsAdded = true

			// Header without ↳
			header := "Risk ⚠️"
			colored = colors.ColorizeFormattedLine(header, 5)
			output.WriteString(colored)
			output.WriteString("\n")

			// Content with ↳ on first line
			firstLine := fmt.Sprintf("  ↳ %s", impactLines[0])
			colored = colors.ColorizeFormattedLine(firstLine, 6)
			output.WriteString(colored)
			output.WriteString("\n")

			// Continuation lines with proper indentation
			for i := 1; i < len(impactLines); i++ {
				continuationLine := fmt.Sprintf("    %s", impactLines[i])
				colored = colors.ColorizeFormattedLine(continuationLine, 6)
				output.WriteString(colored)
				output.WriteString("\n")
			}
		}
	}

	// Remediation section
	if entry.Remediation != "" {
		remediationLines := formatMultilineText(entry.Remediation)
		if len(remediationLines) > 0 {
			if sectionsAdded {
				output.WriteString("\n")
			}
			sectionsAdded = true

			// Header without ↳
			header := "Remediation 🔧"
			colored = colors.ColorizeFormattedLine(header, 5)
			output.WriteString(colored)
			output.WriteString("\n")

			// Content with ↳ on first line
			firstLine := fmt.Sprintf("  ↳ %s", remediationLines[0])
			colored = colors.ColorizeFormattedLine(firstLine, 6)
			output.WriteString(colored)
			output.WriteString("\n")

			// Continuation lines with proper indentation
			for i := 1; i < len(remediationLines); i++ {
				continuationLine := fmt.Sprintf("    %s", remediationLines[i])
				colored = colors.ColorizeFormattedLine(continuationLine, 6)
				output.WriteString(colored)
				output.WriteString("\n")
			}
		}
	}

	// POCs section (limited to 5)
	pocs := formatPOCs(entry.Pocs)
	if len(pocs) > 0 {
		if sectionsAdded {
			output.WriteString("\n")
		}
		sectionsAdded = true

		// Header without ↳
		header := "POCs 🔍"
		colored = colors.ColorizeFormattedLine(header, 5)
		output.WriteString(colored)
		output.WriteString("\n")

		// Limit to 5 items
		displayPocs := pocs
		if len(pocs) > 5 {
			displayPocs = pocs[:5]
		}

		for _, poc := range displayPocs {
			// Wrap long POC lines with proper indentation
			wrappedLines := wrapLongText(poc, 80, "    ")
			for i, line := range wrappedLines {
				if i == 0 {
					colored = colors.ColorizeFormattedLine(fmt.Sprintf("  → %s", line), 6)
				} else {
					colored = colors.ColorizeFormattedLine(fmt.Sprintf("    %s", line), 6)
				}
				output.WriteString(colored)
				output.WriteString("\n")
			}
		}

		// Show "+x more" if there are more items
		if len(pocs) > 5 {
			remaining := len(pocs) - 5
			moreLine := fmt.Sprintf("  → +%d more...", remaining)
			colored = colors.ColorizeFormattedLine(moreLine, 6)
			output.WriteString(colored)
			output.WriteString("\n")
		}
	}

	// References section (limited to 5)
	references := formatCitations(entry.Citations)
	if len(references) > 0 {
		if sectionsAdded {
			output.WriteString("\n")
		}
		sectionsAdded = true

		// Header without ↳
		header := "References 📚"
		colored = colors.ColorizeFormattedLine(header, 5)
		output.WriteString(colored)
		output.WriteString("\n")

		// Limit to 5 items
		displayRefs := references
		if len(references) > 5 {
			displayRefs = references[:5]
		}

		for _, ref := range displayRefs {
			// Wrap long reference lines with proper indentation
			wrappedLines := wrapLongText(ref, 80, "    ")
			for i, line := range wrappedLines {
				if i == 0 {
					colored = colors.ColorizeFormattedLine(fmt.Sprintf("  → %s", line), 6)
				} else {
					colored = colors.ColorizeFormattedLine(fmt.Sprintf("    %s", line), 6)
				}
				output.WriteString(colored)
				output.WriteString("\n")
			}
		}

		// Show "+x more" if there are more items
		if len(references) > 5 {
			remaining := len(references) - 5
			moreLine := fmt.Sprintf("  → +%d more...", remaining)
			colored = colors.ColorizeFormattedLine(moreLine, 6)
			output.WriteString(colored)
			output.WriteString("\n")
		}
	}

	// Nuclei Template section with cloud URL
	if entry.TemplateURI != "" {
		cloudURL := formatNucleiTemplateURL(entry.TemplateURI, entry.DocID)
		if cloudURL != "" {
			if sectionsAdded {
				output.WriteString("\n")
			}
			sectionsAdded = true

			// Header without ↳
			header := "Nuclei Template ⚛️"
			colored = colors.ColorizeFormattedLine(header, 5)
			output.WriteString(colored)
			output.WriteString("\n")

			// Wrap long cloud URL with proper indentation
			wrappedLines := wrapLongText(cloudURL, 80, "    ")
			for i, line := range wrappedLines {
				if i == 0 {
					colored = colors.ColorizeFormattedLine(fmt.Sprintf("  → %s", line), 6)
				} else {
					colored = colors.ColorizeFormattedLine(fmt.Sprintf("    %s", line), 6)
				}
				output.WriteString(colored)
				output.WriteString("\n")
			}
		}
	}

	// Affected Products section (limited to 5)
	products := formatAffectedProducts(entry.AffectedProducts)
	if len(products) > 0 {
		if sectionsAdded {
			output.WriteString("\n")
		}

		// Header without ↳
		header := "Affected Products 🎯"
		colored = colors.ColorizeFormattedLine(header, 5)
		output.WriteString(colored)
		output.WriteString("\n")

		// Limit to 5 items
		displayProducts := products
		if len(products) > 5 {
			displayProducts = products[:5]
		}

		for _, product := range displayProducts {
			colored = colors.ColorizeFormattedLine(fmt.Sprintf("  → %s", product), 6)
			output.WriteString(colored)
			output.WriteString("\n")
		}

		// Show "+x more" if there are more items
		if len(products) > 5 {
			remaining := len(products) - 5
			moreLine := fmt.Sprintf("  → +%d more...", remaining)
			colored = colors.ColorizeFormattedLine(moreLine, 6)
			output.WriteString(colored)
			output.WriteString("\n")
		}
	}

	return strings.TrimRight(output.String(), "\n")
}

// RenderWithColors generates formatted output with color support
func RenderWithColors(entries []*Entry, layout []LayoutLine, totalResults, shownResults int, colors *ColorConfig) string {
	var output strings.Builder

	for i, entry := range entries {
		if i > 0 {
			// Add visual separator between results
			separator := colors.ColorResultSeparator("─────────────────────────────────────────────────────────────────────────")
			output.WriteString(separator)
			output.WriteString("\n\n")
		}

		// Process each layout line
		for _, line := range layout {
			formatted := formatLine(entry, line)
			if formatted != "" {
				// Apply colors to the formatted line
				colored := colors.ColorizeFormattedLine(formatted, line.Line)
				output.WriteString(colored)
				output.WriteString("\n")
			}
		}
	}

	// Add footer with result count (separated from results)
	if len(entries) > 0 {
		output.WriteString("\n")
	}
	footer := fmt.Sprintf("↳ Showing %d of %d total results", shownResults, totalResults)
	coloredFooter := colors.ColorFooter(footer)
	output.WriteString(coloredFooter)
	output.WriteString("\n")

	return output.String()
}

// ParseLayout parses layout JSON into LayoutLine structs
func ParseLayout(layoutJSON []byte) ([]LayoutLine, error) {
	var layout []LayoutLine
	if err := json.Unmarshal(layoutJSON, &layout); err != nil {
		return nil, fmt.Errorf("failed to parse layout JSON: %w", err)
	}
	return layout, nil
}

// formatLine formats a single line according to the layout specification
func formatLine(entry *Entry, line LayoutLine) string {
	// Check if line should be omitted
	if shouldOmitLine(entry, line.OmitIf) {
		return ""
	}

	// Replace placeholders with actual values
	formatted := line.Format
	placeholders := extractPlaceholders(entry)

	for placeholder, value := range placeholders {
		formatted = strings.ReplaceAll(formatted, "{"+placeholder+"}", value)
	}

	// Clean up any remaining empty placeholders and compress separators
	formatted = cleanupSeparators(formatted)

	return formatted
}

// extractPlaceholders extracts all placeholder values from an entry
func extractPlaceholders(entry *Entry) map[string]string {
	placeholders := make(map[string]string)

	// Basic fields
	placeholders["doc_id"] = entry.DocID
	placeholders["severity"] = capitalizeFirst(entry.Severity)
	placeholders["title"] = entry.Name
	placeholders["age_in_days"] = strconv.Itoa(entry.AgeInDays)
	placeholders["epss_score"] = formatFloat(entry.EpssScore)
	placeholders["cvss_score"] = formatFloat(entry.CvssScore)

	// Authors list
	placeholders["authors"] = truncateList(entry.Author, 2)

	// Exposure
	if entry.Exposure != nil {
		placeholders["exposure"] = formatExposure(entry.Exposure.MaxHosts)
	} else {
		placeholders["exposure"] = "unknown"
	}

	// Vendors and products
	vendors := extractDistinctVendors(entry.AffectedProducts)
	products := extractDistinctProducts(entry.AffectedProducts)
	placeholders["vendors"] = truncateList(vendors, 2)
	placeholders["products"] = truncateList(products, 2)

	// Boolean flags
	placeholders["patch"] = formatBoolCheckmark(entry.IsPatchAvailable)
	placeholders["kev"] = formatBoolCheckmark(entry.IsKev)
	placeholders["template"] = formatBoolCheckmark(entry.IsTemplate)
	placeholders["exploit_seen"] = formatBoolCheckmark(exploitSeen(entry))

	// POC count
	placeholders["poc_count"] = formatPocCount(entry.PocCount)

	// HackerOne
	hackeroneActive := entry.H1 != nil && entry.H1.Reports > 0
	placeholders["hackerone"] = formatBoolCheckmark(hackeroneActive)

	// Tags
	placeholders["tags"] = truncateList(entry.Tags, 3)

	// Security-focused placeholders
	placeholders["exploit_status"] = getExploitStatus(entry)
	placeholders["research_priority"] = getResearchPriority(entry)

	// Enhanced age with urgency
	placeholders["age_urgency"] = formatAgeUrgency(entry.AgeInDays)

	// Enhanced CVSS with visual indicators
	placeholders["cvss_enhanced"] = formatCVSSEnhanced(entry.CvssScore)

	// Enhanced EPSS with probability
	placeholders["epss_enhanced"] = formatEPSSEnhanced(entry.EpssScore)

	// Enhanced KEV status
	placeholders["kev_enhanced"] = formatKEVEnhanced(entry)

	// Conditional placeholders with labels (only show when data exists)
	var exposurePart, vendorsPart, productsPart string

	// Check what data we have
	hasExposure := entry.Exposure != nil && entry.Exposure.MaxHosts > 0
	hasVendors := len(vendors) > 0
	hasProducts := len(products) > 0

	// Build parts with appropriate prefixes
	if hasExposure {
		exposurePart = "Exposure: " + formatExposure(entry.Exposure.MaxHosts)
	}
	if hasVendors {
		vendorsPart = "Vendors: " + truncateList(vendors, 2)
	}
	if hasProducts {
		productsPart = "Products: " + truncateList(products, 2)
	}

	// Combine parts with proper separators
	var parts []string
	if exposurePart != "" {
		parts = append(parts, exposurePart)
	}
	if vendorsPart != "" {
		parts = append(parts, vendorsPart)
	}
	if productsPart != "" {
		parts = append(parts, productsPart)
	}

	// Create the final conditional line
	if len(parts) > 0 {
		placeholders["exposure_vendors_products"] = "  ↳ " + strings.Join(parts, " | ")
	} else {
		placeholders["exposure_vendors_products"] = ""
	}

	// Detailed sections for single vulnerability view
	placeholders["description"] = entry.Description
	placeholders["impact"] = entry.Impact
	placeholders["remediation"] = entry.Remediation
	placeholders["template_uri"] = entry.TemplateURI

	return placeholders
}

// shouldOmitLine checks if a line should be omitted based on omit_if conditions
func shouldOmitLine(entry *Entry, omitIf []string) bool {
	for _, condition := range omitIf {
		if evaluateCondition(entry, condition) {
			return true
		}
	}
	return false
}

// evaluateCondition evaluates a single omit_if condition
func evaluateCondition(entry *Entry, condition string) bool {
	switch condition {
	case "authors.length == 0":
		return len(entry.Author) == 0
	case "epss_score == 0":
		return entry.EpssScore == 0
	case "cvss_score == 0":
		return entry.CvssScore == 0
	case "exposure == 0":
		return entry.Exposure == nil || entry.Exposure.MaxHosts == 0
	case "vendors.length == 0":
		return len(extractDistinctVendors(entry.AffectedProducts)) == 0
	case "products.length == 0":
		return len(extractDistinctProducts(entry.AffectedProducts)) == 0
	case "tags.length == 0":
		return len(entry.Tags) == 0
	case "description.empty":
		return strings.TrimSpace(entry.Description) == ""
	case "impact.empty":
		return strings.TrimSpace(entry.Impact) == ""
	case "remediation.empty":
		return strings.TrimSpace(entry.Remediation) == ""
	case "pocs.length == 0":
		return len(entry.Pocs) == 0
	case "citations.length == 0":
		return len(entry.Citations) == 0
	case "template_uri.empty":
		return strings.TrimSpace(entry.TemplateURI) == ""
	case "affected_products.length == 0":
		return len(entry.AffectedProducts) == 0
	}
	return false
}

// cleanupSeparators removes empty placeholders and compresses separators
func cleanupSeparators(formatted string) string {
	// Remove empty placeholders (anything that looks like {placeholder})
	result := formatted
	for strings.Contains(result, "{") && strings.Contains(result, "}") {
		start := strings.Index(result, "{")
		end := strings.Index(result[start:], "}")
		if end == -1 {
			break
		}
		end += start
		result = result[:start] + result[end+1:]
	}

	// Clean up multiple separators
	result = strings.ReplaceAll(result, " | |", " |")
	result = strings.ReplaceAll(result, "| |", "|")
	result = strings.ReplaceAll(result, " |  |", " |")

	// Clean up leading/trailing separators, but preserve leading spaces
	result = strings.TrimRight(result, " \t")
	result = strings.TrimPrefix(result, "|")
	result = strings.TrimSuffix(result, "|")
	result = strings.TrimRight(result, " \t")

	return result
}

// formatFloat formats a float64 to a reasonable precision
func formatFloat(f float64) string {
	if f == 0 {
		return "0"
	}
	return fmt.Sprintf("%.4g", f)
}
