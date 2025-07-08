package renderer

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/cvemap"
)

// truncateList formats a string slice to show up to specified items, then " +N" for additional items
func truncateList(items []string, maxItems int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= maxItems {
		return strings.Join(items, ", ")
	}
	displayed := strings.Join(items[:maxItems], ", ")
	remaining := len(items) - maxItems
	return fmt.Sprintf("%s +%d", displayed, remaining)
}

// formatExposure formats exposure count: 0 -> "unknown", 1-999 -> as is, 1000+ -> "~12.3K"
func formatExposure(count int) string {
	if count == 0 {
		return "unknown"
	}
	if count < 1000 {
		return fmt.Sprintf("%d", count)
	}
	// Format as K with one decimal place
	k := float64(count) / 1000.0
	return fmt.Sprintf("~%.1fK", k)
}

// formatBoolCheckmark formats boolean values: true -> "✔", false -> "✘"
func formatBoolCheckmark(value bool) string {
	if value {
		return "✔"
	}
	return "✘"
}

// formatPocCount formats POC count: 0 -> "✘", otherwise numeric count
func formatPocCount(count int) string {
	if count == 0 {
		return "✘"
	}
	return fmt.Sprintf("%d", count)
}

// capitalizeFirst capitalizes the first letter of a string
func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// truncateProductName truncates product names that are too long
func truncateProductName(productName string, maxLength int) string {
	if len(productName) <= maxLength {
		return productName
	}
	return productName[:maxLength-3] + "..."
}

// extractDistinctVendors extracts distinct vendors from a slice of ProductInfo
func extractDistinctVendors(products []*cvemap.ProductInfo) []string {
	seen := make(map[string]bool)
	var vendors []string
	for _, product := range products {
		if product != nil && product.Vendor != "" && !seen[product.Vendor] {
			seen[product.Vendor] = true
			// Truncate long vendor names to prevent line wrapping
			truncatedName := truncateProductName(product.Vendor, 15)
			vendors = append(vendors, truncatedName)
		}
	}
	return vendors
}

// extractDistinctProducts extracts distinct product names from a slice of ProductInfo
func extractDistinctProducts(products []*cvemap.ProductInfo) []string {
	seen := make(map[string]bool)
	var productNames []string
	for _, product := range products {
		if product != nil && product.Product != "" && !seen[product.Product] {
			seen[product.Product] = true
			// Truncate long product names to prevent line wrapping
			truncatedName := truncateProductName(product.Product, 20)
			productNames = append(productNames, truncatedName)
		}
	}
	return productNames
}

// exploitSeen determines if a vulnerability has been exploited in the wild
func exploitSeen(entry *Entry) bool {
	// Check POC sources for exploit keywords
	exploitKeywords := []string{"exploit", "exploiting", "exploitation", "exploitable"}
	for _, poc := range entry.Pocs {
		if poc != nil && poc.Source != "" {
			sourceLower := strings.ToLower(poc.Source)
			for _, keyword := range exploitKeywords {
				if strings.Contains(sourceLower, keyword) {
					return true
				}
			}
		}
	}

	// Check citation URLs for exploit domains
	exploitDomains := []string{"exploit-db.com", "exploitdb.com", "metasploit.com"}
	for _, citation := range entry.Citations {
		if citation != nil && citation.URL != "" {
			urlLower := strings.ToLower(citation.URL)
			for _, domain := range exploitDomains {
				if strings.Contains(urlLower, domain) {
					return true
				}
			}
		}
	}

	// Check description and impact for exploit phrases
	exploitPhrases := []string{
		"exploited in the wild",
		"actively exploited",
		"used in attacks",
		"real-world exploitation",
	}

	texts := []string{entry.Description, entry.Impact}
	for _, text := range texts {
		if text != "" {
			textLower := strings.ToLower(text)
			for _, phrase := range exploitPhrases {
				if strings.Contains(textLower, phrase) {
					return true
				}
			}
		}
	}

	return false
}

// getExploitStatus returns exploit availability status
func getExploitStatus(entry *Entry) string {
	if exploitSeen(entry) || entry.PocCount > 0 || entry.IsKev {
		return "EXPLOITS AVAILABLE"
	}
	return "No exploits"
}

// getResearchPriority returns research priority based on various factors
func getResearchPriority(entry *Entry) string {
	if entry.IsKev {
		return "IMMEDIATE"
	}

	if entry.CvssScore >= 9.0 && entry.EpssScore >= 0.5 {
		return "URGENT"
	}

	if entry.CvssScore >= 7.0 && (exploitSeen(entry) || entry.PocCount > 0) {
		return "HIGH"
	}

	if entry.CvssScore >= 7.0 || entry.EpssScore >= 0.3 {
		return "MEDIUM"
	}

	return "LOW"
}

// formatAgeUrgency formats age with urgency indicators
func formatAgeUrgency(ageInDays int) string {
	if ageInDays <= 7 {
		return fmt.Sprintf("%dd (NEW)", ageInDays)
	} else if ageInDays <= 30 {
		return fmt.Sprintf("%dd (RECENT)", ageInDays)
	}
	return fmt.Sprintf("%dd", ageInDays)
}

// formatCVSSEnhanced formats CVSS score with visual indicators
func formatCVSSEnhanced(score float64) string {
	return fmt.Sprintf("%.1f", score)
}

// formatEPSSEnhanced formats EPSS score with probability indicators
func formatEPSSEnhanced(score float64) string {
	if score >= 0.7 {
		return fmt.Sprintf("%.4f (HIGH)", score)
	} else if score >= 0.4 {
		return fmt.Sprintf("%.4f (MED)", score)
	}
	return fmt.Sprintf("%.4f", score)
}

// formatKEVEnhanced formats KEV status with source information
func formatKEVEnhanced(entry *Entry) string {
	if !entry.IsKev {
		return "✘"
	}

	// Extract sources from KEV info
	sources := make([]string, 0)
	seen := make(map[string]bool)

	for _, kev := range entry.Kev {
		if kev != nil && kev.Source != "" {
			// Normalize source name for better display
			source := strings.ToUpper(kev.Source)
			if !seen[source] {
				sources = append(sources, source)
				seen[source] = true
			}
		}
	}

	if len(sources) == 0 {
		return "✔"
	}

	// Format: ✔ (CISA) or ✔ (CISA, VulCheck)
	return fmt.Sprintf("✔ (%s)", strings.Join(sources, ", "))
}

// formatAffectedProducts formats affected products with vendor info (max 10 items)
func formatAffectedProducts(products []*cvemap.ProductInfo) []string {
	if len(products) == 0 {
		return nil
	}

	var formatted []string
	seen := make(map[string]bool)
	maxProducts := 10

	for _, product := range products {
		if product != nil && product.Product != "" && len(formatted) < maxProducts {
			key := fmt.Sprintf("%s (%s)", product.Product, product.Vendor)
			if !seen[key] {
				seen[key] = true
				formatted = append(formatted, key)
			}
		}
	}

	return formatted
}

// formatPOCs formats POCs with sources (wrapped URLs)
func formatPOCs(pocs []*cvemap.POC) []string {
	if len(pocs) == 0 {
		return nil
	}

	var formatted []string
	for _, poc := range pocs {
		if poc != nil && poc.URL != "" {
			url := poc.URL

			source := "unknown"
			if poc.Source != "" {
				source = poc.Source
			}
			line := fmt.Sprintf("%s (%s)", url, source)
			formatted = append(formatted, line)
		}
	}

	return formatted
}

// formatCitations formats citations with sources (wrapped URLs, no tags)
func formatCitations(citations []*cvemap.Citation) []string {
	if len(citations) == 0 {
		return nil
	}

	var formatted []string
	for _, citation := range citations {
		if citation != nil && citation.URL != "" {
			url := citation.URL

			// Add source if available (no tags)
			if citation.Source != "" {
				line := fmt.Sprintf("%s (%s)", url, citation.Source)
				formatted = append(formatted, line)
			} else {
				formatted = append(formatted, url)
			}
		}
	}

	return formatted
}

// formatMultilineText formats multiline text with proper indentation
func formatMultilineText(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}

	lines := strings.Split(text, "\n")
	var formatted []string

	for _, line := range lines {
		// Trim whitespace but preserve intentional formatting
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			formatted = append(formatted, trimmed)
		}
	}

	return formatted
}

// formatNucleiTemplateURL converts local template path to cloud ProjectDiscovery URL
func formatNucleiTemplateURL(uri string, docID string) string {
	if uri == "" {
		return ""
	}

	// If it's already a full URL, return as is
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}

	// Convert to cloud ProjectDiscovery URL using doc_id
	// Example: CVE-2025-5777 -> https://cloud.projectdiscovery.io/library/CVE-2025-5777
	return fmt.Sprintf("https://cloud.projectdiscovery.io/library/%s", docID)
}

// wrapLongText wraps long text to multiple lines with proper indentation
func wrapLongText(text string, maxWidth int, indent string) []string {
	if len(text) <= maxWidth {
		return []string{text}
	}

	var lines []string
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{text}
	}

	currentLine := words[0]

	for i := 1; i < len(words); i++ {
		if len(currentLine)+1+len(words[i]) <= maxWidth {
			currentLine += " " + words[i]
		} else {
			lines = append(lines, currentLine)
			currentLine = indent + words[i]
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}
