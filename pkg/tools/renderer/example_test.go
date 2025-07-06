package renderer

import (
	"fmt"
	"log"

	"github.com/projectdiscovery/cvemap"
)

func ExampleRender() {
	// Define layout configuration
	layoutJSON := `[
		{
			"line": 1,
			"format": "[{doc_id}] {severity} - {title}",
			"omit_if": []
		},
		{
			"line": 2,
			"format": "↳ Template Authors: {authors} | Vuln Age: {age_in_days}d | EPSS: {epss_score} | CVSS: {cvss_score}",
			"omit_if": ["authors.length == 0", "epss_score == 0", "cvss_score == 0"]
		},
		{
			"line": 3,
			"format": "↳ Exposure: {exposure} | Vendors: {vendors} | Products: {products}",
			"omit_if": ["exposure == 0", "vendors.length == 0", "products.length == 0"]
		},
		{
			"line": 4,
			"format": "↳ Patch: {patch} | POCs: {poc_count} | KEV: {kev} | Nuclei Template: {template} | Exploit Seen: {exploit_seen} | HackerOne: {hackerone}",
			"omit_if": []
		},
		{
			"line": 5,
			"format": "↳ Tags: {tags}",
			"omit_if": ["tags.length == 0"]
		}
	]`

	// Parse layout
	layout, err := ParseLayout([]byte(layoutJSON))
	if err != nil {
		log.Fatal(err)
	}

	// Create sample vulnerability data
	vuln := &cvemap.Vulnerability{
		DocID:     "CVE-2024-1234",
		Name:      "Example Vulnerability",
		Severity:  "critical",
		Author:    []string{"security-team", "researcher"},
		AgeInDays: 30,
		EpssScore: 0.85,
		CvssScore: 9.1,
		Exposure: &cvemap.VulnExposure{
			MaxHosts: 15000,
		},
		AffectedProducts: []*cvemap.ProductInfo{
			{Vendor: "example-corp", Product: "webapp"},
			{Vendor: "example-corp", Product: "api-server"},
		},
		IsPatchAvailable: true,
		PocCount:         2,
		IsKev:            true,
		Kev: []*cvemap.KevInfo{
			{Source: "cisa"},
			{Source: "vulcheck"},
		},
		IsTemplate:  false,
		H1:          &cvemap.H1Stats{Reports: 5},
		Tags:        []string{"rce", "auth-bypass"},
		Description: "Critical vulnerability that has been exploited in the wild",
	}

	// Convert to Entry and render
	entry := FromVulnerability(vuln)
	entries := []*Entry{entry}

	result := Render(entries, layout, 1, 1)
	fmt.Println(result)

	// Output:
	// [CVE-2024-1234] Critical - Example Vulnerability
	// ↳ Template Authors: security-team, researcher | Vuln Age: 30d | EPSS: 0.85 | CVSS: 9.1
	// ↳ Exposure: ~15.0K | Vendors: example-corp | Products: webapp, api-server
	// ↳ Patch: ✔ | POCs: 2 | KEV: ✔ (CISA, VULCHECK) | Nuclei Template: ✘ | Exploit Seen: ✔ | HackerOne: ✔
	// ↳ Tags: rce, auth-bypass
	// ↳ Showing 1 of 1 total results
}
