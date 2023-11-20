package main

import (
	"github.com/projectdiscovery/goflags"
)

type Options struct {
	cveIds             goflags.StringSlice
	cweIds             goflags.StringSlice
	vendor             goflags.StringSlice
	product            goflags.StringSlice
	severity           goflags.StringSlice
	cvssScore          goflags.StringSlice
	//cvssMetrics        goflags.StringSlice
	epssPercentile     goflags.StringSlice
	//year               goflags.StringSlice
	assignees          goflags.StringSlice
	reference          goflags.StringSlice
	//vulnType           goflags.StringSlice
	includeColumns     []string
	excludeColumns     []string
	listId			   bool
	epssScore          string
	cpe                string
	vulnStatus         string
	age                string
	kev                string
	//trending           bool
	hackerone          string
	hasNucleiTemplate  string
	hasPoc             string
	json               bool
	limit              int
	version            bool
	disableUpdateCheck bool
	silent             bool
	verbose            bool
}

type CVEBulkData struct {
	ResultCount int       `json:"result_count"`
	Cves        []CVEData `json:"cves"`
}

type CVEData struct {
	CveID          string       `json:"cve_id"`
	CveDescription string       `json:"cve_description"`
	Severity       string       `json:"severity"`
	CvssScore      float64      `json:"cvss_score"`
	CvssMetrics    *CvssMetrics `json:"cvss_metrics"`
	Weaknesses     []struct {
		CWEID   string `json:"cwe_id"`
		CWEName string `json:"cwe_name,omitempty"`
	} `json:"weaknesses"`
	Epss struct {
		Score      float64 `json:"epss_score"`
		Percentile float64 `json:"epss_percentile"`
	} `json:"epss"`
	Cpe       *OutputCpe `json:"cpe,omitempty"`
	Reference []string   `json:"reference"`
	Poc       []struct {
		URL     string `json:"url"`
		Source  string `json:"source"`
		AddedAt string `json:"added_at"`
	} `json:"poc,omitempty"`
	VendorAdvisory  *string          `json:"vendor_advisory,omitempty"`
	Patch           []string         `json:"patch_url,omitempty"`
	IsTemplate      bool             `json:"is_template"`
	NucleiTemplates *NucleiTemplates `json:"nuclei_templates,omitempty"`
	IsKev           bool             `json:"is_exploited"`
	Kev             *KevObject       `json:"kev,omitempty"`
	Assignee        string           `json:"assignee"`
	PublishedAt     string           `json:"published_at"`
	UpdatedAt       string           `json:"updated_at"`
	Activity        struct {
		Rank  int `json:"rank"`
		Count int `json:"count"`
	} `json:"activity"`
	Hackerone struct {
		Rank  int `json:"rank"`
		Count int `json:"count"`
	} `json:"hackerone"`
	AgeInDays     int               `json:"age_in_days"`
	VulnStatus    string            `json:"vuln_status"`
	IsPoc         bool              `json:"is_poc"`
	IsRemote      bool              `json:"is_remote"`
	VulnerableCPE []string          `json:"vulnerable_cpe,omitempty"`
	Shodan        *OutputShodanData `json:"shodan,omitempty"`
}

type CvssMetrics struct {
	Cvss2  *Cvss2  `json:"cvss2,omitempty"`
	Cvss30 *Cvss30 `json:"cvss30,omitempty"`
	Cvss31 *Cvss31 `json:"cvss31,omitempty"`
}

type Cvss2 struct {
	Score    float64 `json:"score"`
	Vector   string  `json:"vector"`
	Severity string  `json:"severity"`
}

type Cvss30 struct {
	Score    float64 `json:"score"`
	Vector   string  `json:"vector"`
	Severity string  `json:"severity"`
}

type Cvss31 struct {
	Score    float64 `json:"score"`
	Vector   string  `json:"vector"`
	Severity string  `json:"severity"`
}

type OutputCpe struct {
	Cpe      *string `json:"cpe,omitempty"`
	Vendor   *string `json:"vendor,omitempty"`
	Product  *string `json:"product,omitempty"`
	Platform *string `json:"framework,omitempty"`
}

type NucleiTemplates struct {
	TemplateURL   *string `json:"template_url,omitempty"`
	TemplateIssue *string `json:"template_issue,omitempty"`
	TemplatePR    *string `json:"template_pr,omitempty"`
}

type KevObject struct {
	AddedDate string `json:"added_date"`
	DueDate   string `json:"due_date"`
}

type OutputShodanData struct {
	Count int      `json:"count"`
	Query []string `json:"query"`
}
