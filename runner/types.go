package runner

type CVEBulkData struct {
	ResultCount  int       `json:"result_count"`
	TotalResults int       `json:"total_results"`
	Cves         []CVEData `json:"cves"`
}

type CVEData struct {
	CveID          string       `json:"cve_id,omitempty"`
	CveDescription string       `json:"cve_description,omitempty"`
	Severity       string       `json:"severity,omitempty"`
	CvssScore      float64      `json:"cvss_score,omitempty"`
	CvssMetrics    *CvssMetrics `json:"cvss_metrics,omitempty"`
	Weaknesses     []struct {
		CWEID   string `json:"cwe_id"`
		CWEName string `json:"cwe_name,omitempty"`
	} `json:"weaknesses,omitempty"`
	Epss struct {
		Score      float64 `json:"epss_score"`
		Percentile float64 `json:"epss_percentile"`
	} `json:"epss,omitempty"`
	Cpe       *OutputCpe `json:"cpe,omitempty"`
	Reference []string   `json:"reference,omitempty"`
	Poc       []struct {
		URL     string `json:"url"`
		Source  string `json:"source"`
		AddedAt string `json:"added_at"`
	} `json:"poc,omitempty"`
	VendorAdvisory  *string          `json:"vendor_advisory,omitempty"`
	Patch           []string         `json:"patch_url,omitempty"`
	IsTemplate      bool             `json:"is_template,omitempty"`
	NucleiTemplates *NucleiTemplates `json:"nuclei_templates,omitempty"`
	IsKev           bool             `json:"is_exploited,omitempty"`
	Kev             *KevObject       `json:"kev,omitempty"`
	Assignee        string           `json:"assignee,omitempty"`
	PublishedAt     string           `json:"published_at,omitempty"`
	UpdatedAt       string           `json:"updated_at,omitempty"`
	Activity        struct {
		Rank  int `json:"rank"`
		Count int `json:"count"`
	} `json:"activity,omitempty"`
	Hackerone struct {
		Rank  int `json:"rank"`
		Count int `json:"count"`
	} `json:"hackerone,omitempty"`
	AgeInDays     int               `json:"age_in_days,omitempty"`
	VulnStatus    string            `json:"vuln_status,omitempty"`
	IsPoc         bool              `json:"is_poc,omitempty"`
	IsRemote      bool              `json:"is_remote,omitempty"`
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

type ErrorMessage struct {
	Message string `json:"message"`
}

type CVEIdList struct {
	Cves []string `json:"cves"`
}