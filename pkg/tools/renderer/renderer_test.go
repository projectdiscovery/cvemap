package renderer

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/cvemap"
)

func TestRender(t *testing.T) {
	// Create test entry
	entry := &Entry{
		DocID:    "placeholder-id",
		Severity: "high",
		Name:     "Placeholder Vulnerability Title",
		Author:   []string{"author1", "author2", "author3", "author4"},
		Exposure: &cvemap.VulnExposure{
			MaxHosts: 42100,
		},
		EpssScore: 0.0042,
		CvssScore: 8.8,
		AgeInDays: 123,
		AffectedProducts: []*cvemap.ProductInfo{
			{Vendor: "vendor1", Product: "product1"},
			{Vendor: "vendor2", Product: "product2"},
			{Vendor: "vendor3", Product: "product3"},
		},
		IsPatchAvailable: true,
		PocCount:         3,
		IsKev:            true,
		Kev: []*cvemap.KevInfo{
			{Source: "cisa"},
		},
		IsTemplate: true,
		H1:         &cvemap.H1Stats{Reports: 5},
		Tags:       []string{"cve", "jira", "misconfig"},
		Pocs: []*cvemap.POC{
			{Source: "exploit-db"},
		},
	}

	// Create test layout (matching the current security-focused layout)
	layout := []LayoutLine{
		{
			Line:   1,
			Format: "[{doc_id}] {severity} - {title}",
			OmitIf: []string{},
		},
		{
			Line:   2,
			Format: "  ↳ Priority: {research_priority} | {exploit_status} | Vuln Age: {age_urgency}",
			OmitIf: []string{},
		},
		{
			Line:   3,
			Format: "  ↳ CVSS: {cvss_enhanced} | EPSS: {epss_enhanced} | KEV: {kev_enhanced}",
			OmitIf: []string{"cvss_score == 0", "epss_score == 0"},
		},
		{
			Line:   4,
			Format: "  ↳ Exposure: {exposure} | Vendors: {vendors} | Products: {products}",
			OmitIf: []string{"exposure == 0", "vendors.length == 0", "products.length == 0"},
		},
		{
			Line:   5,
			Format: "  ↳ Patch: {patch} | POCs: {poc_count} | Nuclei Template: {template} | HackerOne: {hackerone}",
			OmitIf: []string{},
		},
		{
			Line:   6,
			Format: "  ↳ Template Authors: {authors}",
			OmitIf: []string{"authors.length == 0"},
		},
	}

	entries := []*Entry{entry}
	result := RenderWithColors(entries, layout, 1, 1, NoColorConfig())

	expected := `[placeholder-id] High - Placeholder Vulnerability Title
  ↳ Priority: IMMEDIATE | EXPLOITS AVAILABLE | Vuln Age: 123d
  ↳ CVSS: 8.8 | EPSS: 0.0042 | KEV: ✔ (CISA)
  ↳ Exposure: ~42.1K | Vendors: vendor1, vendor2 +1 | Products: product1, product2 +1
  ↳ Patch: ✔ | POCs: 3 | Nuclei Template: ✔ | HackerOne: ✔
  ↳ Template Authors: author1, author2 +2

↳ Showing 1 of 1 total results
`

	if result != expected {
		t.Errorf("Expected:\n%s\n\nGot:\n%s", expected, result)
	}
}

func TestParseLayout(t *testing.T) {
	layoutJSON := `[
		{
			"line": 1,
			"format": "[{doc_id}] {severity} - {title}",
			"omit_if": []
		},
		{
			"line": 2,
			"format": "↳ Template Authors: {authors}",
			"omit_if": ["authors.length == 0"]
		}
	]`

	layout, err := ParseLayout([]byte(layoutJSON))
	if err != nil {
		t.Fatalf("Failed to parse layout: %v", err)
	}

	if len(layout) != 2 {
		t.Errorf("Expected 2 layout lines, got %d", len(layout))
	}

	if layout[0].Line != 1 {
		t.Errorf("Expected line 1, got %d", layout[0].Line)
	}

	if layout[0].Format != "[{doc_id}] {severity} - {title}" {
		t.Errorf("Unexpected format: %s", layout[0].Format)
	}
}

func TestTruncateList(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		maxItems int
		expected string
	}{
		{
			name:     "empty list",
			items:    []string{},
			maxItems: 3,
			expected: "",
		},
		{
			name:     "under limit",
			items:    []string{"item1", "item2"},
			maxItems: 3,
			expected: "item1, item2",
		},
		{
			name:     "at limit",
			items:    []string{"item1", "item2", "item3"},
			maxItems: 3,
			expected: "item1, item2, item3",
		},
		{
			name:     "over limit",
			items:    []string{"item1", "item2", "item3", "item4", "item5"},
			maxItems: 3,
			expected: "item1, item2, item3 +2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateList(tt.items, tt.maxItems)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFormatExposure(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		expected string
	}{
		{
			name:     "zero",
			count:    0,
			expected: "unknown",
		},
		{
			name:     "small number",
			count:    500,
			expected: "500",
		},
		{
			name:     "thousand",
			count:    1000,
			expected: "~1.0K",
		},
		{
			name:     "large number",
			count:    42100,
			expected: "~42.1K",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatExposure(tt.count)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFormatBoolCheckmark(t *testing.T) {
	tests := []struct {
		name     string
		value    bool
		expected string
	}{
		{
			name:     "true",
			value:    true,
			expected: "✔",
		},
		{
			name:     "false",
			value:    false,
			expected: "✘",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBoolCheckmark(tt.value)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestFormatPocCount(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		expected string
	}{
		{
			name:     "zero",
			count:    0,
			expected: "✘",
		},
		{
			name:     "positive",
			count:    3,
			expected: "3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatPocCount(tt.count)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestExploitSeen(t *testing.T) {
	tests := []struct {
		name     string
		entry    *Entry
		expected bool
	}{
		{
			name: "exploit in POC source",
			entry: &Entry{
				Pocs: []*cvemap.POC{
					{Source: "exploit-db"},
				},
			},
			expected: true,
		},
		{
			name: "exploit in citation URL",
			entry: &Entry{
				Citations: []*cvemap.Citation{
					{URL: "https://exploit-db.com/exploits/1234"},
				},
			},
			expected: true,
		},
		{
			name: "exploit phrase in description",
			entry: &Entry{
				Description: "This vulnerability has been exploited in the wild",
			},
			expected: true,
		},
		{
			name: "exploit phrase in impact",
			entry: &Entry{
				Impact: "This is actively exploited by attackers",
			},
			expected: true,
		},
		{
			name: "no exploit indicators",
			entry: &Entry{
				Description: "Regular vulnerability",
				Impact:      "Low impact",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := exploitSeen(tt.entry)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestExtractDistinctVendors(t *testing.T) {
	products := []*cvemap.ProductInfo{
		{Vendor: "vendor1", Product: "product1"},
		{Vendor: "vendor2", Product: "product2"},
		{Vendor: "vendor1", Product: "product3"}, // duplicate vendor
		{Vendor: "vendor3", Product: "product4"},
	}

	vendors := extractDistinctVendors(products)
	expected := []string{"vendor1", "vendor2", "vendor3"}

	if len(vendors) != len(expected) {
		t.Errorf("Expected %d vendors, got %d", len(expected), len(vendors))
	}

	// Check that all expected vendors are present
	vendorMap := make(map[string]bool)
	for _, vendor := range vendors {
		vendorMap[vendor] = true
	}

	for _, expectedVendor := range expected {
		if !vendorMap[expectedVendor] {
			t.Errorf("Expected vendor %q not found", expectedVendor)
		}
	}
}

func TestExtractDistinctProducts(t *testing.T) {
	products := []*cvemap.ProductInfo{
		{Vendor: "vendor1", Product: "product1"},
		{Vendor: "vendor2", Product: "product2"},
		{Vendor: "vendor1", Product: "product1"}, // duplicate product
		{Vendor: "vendor3", Product: "product3"},
	}

	productNames := extractDistinctProducts(products)
	expected := []string{"product1", "product2", "product3"}

	if len(productNames) != len(expected) {
		t.Errorf("Expected %d products, got %d", len(expected), len(productNames))
	}

	// Check that all expected products are present
	productMap := make(map[string]bool)
	for _, product := range productNames {
		productMap[product] = true
	}

	for _, expectedProduct := range expected {
		if !productMap[expectedProduct] {
			t.Errorf("Expected product %q not found", expectedProduct)
		}
	}
}

func TestRenderDetailed(t *testing.T) {
	// Create test entry with all fields
	entry := &Entry{
		DocID:       "CVE-2025-5777",
		Severity:    "critical",
		Name:        "Citrix NetScaler Memory Disclosure - CitrixBleed 2",
		Description: "Insufficient input validation leading to memory overread on the NetScaler Management Interface NetScaler ADC and NetScaler Gateway",
		Impact:      "Remote attackers can exploit this vulnerability to cause memory disclosure and potentially gain unauthorized access to sensitive information.",
		Remediation: "Update to the latest version of NetScaler ADC and NetScaler Gateway. Apply the vendor-provided patches immediately.",
		AgeInDays:   8,
		CvssScore:   9.8,
		EpssScore:   0.0417,
		IsKev:       true,
		Kev: []*cvemap.KevInfo{
			{Source: "vulncheck"},
		},
		IsPatchAvailable: false,
		PocCount:         8,
		IsTemplate:       true,
		H1:               &cvemap.H1Stats{Reports: 0},
		TemplateURI:      "http/cves/2025/CVE-2025-5777.yaml",
		Pocs: []*cvemap.POC{
			{URL: "https://github.com/RaR1991/citrix_bleed_2", Source: "gh-nomi-sec"},
			{URL: "https://github.com/nocerainfosec/cve-2025-5777", Source: "gh-nomi-sec"},
		},
		Citations: []*cvemap.Citation{
			{URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-5777", Source: "nuclei_template"},
			{URL: "https://dashboard.shadowserver.org/statistics/honeypot/vulnerability/map/?day=2025-05-05&host_type=src&vuln=CVE-2025-5777", Source: "vulncheck"},
		},
		AffectedProducts: []*cvemap.ProductInfo{
			{Vendor: "citrix", Product: "netscaler_adc"},
			{Vendor: "citrix", Product: "netscaler_gateway"},
		},
	}

	result := RenderDetailed(entry, NoColorConfig())

	// Check that the result contains the cloud URL, not the local path
	if !strings.Contains(result, "https://cloud.projectdiscovery.io/library/CVE-2025-5777") {
		t.Errorf("Expected cloud URL in result, but got: %s", result)
	}

	// Check that the result does NOT contain the local path
	if strings.Contains(result, "http/cves/2025/CVE-2025-5777.yaml") {
		t.Errorf("Result should not contain local path, but got: %s", result)
	}

	// Check that all major sections are present
	expectedSections := []string{
		"Nuclei Template ⚛️",
		"Summary 📝",
		"Risk ⚠️",
		"Remediation 🔧",
		"POCs 🔍",
		"References 📚",
		"Affected Products 🎯",
	}

	for _, section := range expectedSections {
		if !strings.Contains(result, section) {
			t.Errorf("Expected section %q in result, but got: %s", section, result)
		}
	}

	// Check the format of textual sections (should have ↳ for content)
	if !strings.Contains(result, "  ↳ Insufficient input validation") {
		t.Errorf("Expected textual content to start with '  ↳', but got: %s", result)
	}

	// Check the format of list sections (should have → for items)
	if !strings.Contains(result, "  → https://github.com/") {
		t.Errorf("Expected list items to start with '  →', but got: %s", result)
	}
}

func TestFormatNucleiTemplateURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		docID    string
		expected string
	}{
		{
			name:     "local path",
			input:    "http/cves/2025/CVE-2025-5777.yaml",
			docID:    "CVE-2025-5777",
			expected: "https://cloud.projectdiscovery.io/library/CVE-2025-5777",
		},
		{
			name:     "local path with leading slash",
			input:    "/http/cves/2025/CVE-2025-5777.yaml",
			docID:    "CVE-2025-5777",
			expected: "https://cloud.projectdiscovery.io/library/CVE-2025-5777",
		},
		{
			name:     "already full URL",
			input:    "https://cloud.projectdiscovery.io/library/CVE-2025-5777",
			docID:    "CVE-2025-5777",
			expected: "https://cloud.projectdiscovery.io/library/CVE-2025-5777",
		},
		{
			name:     "empty string",
			input:    "",
			docID:    "CVE-2025-5777",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatNucleiTemplateURL(tt.input, tt.docID)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}
