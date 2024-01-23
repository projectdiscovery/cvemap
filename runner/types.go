package runner

import "time"

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
	IsTemplate      bool             `json:"is_template"`
	NucleiTemplates *NucleiTemplates `json:"nuclei_templates,omitempty"`
	IsKev           bool             `json:"is_exploited"`
	Kev             *KevObject       `json:"kev,omitempty"`
	Assignee        string           `json:"assignee,omitempty"`
	PublishedAt     string           `json:"published_at,omitempty"`
	UpdatedAt       string           `json:"updated_at,omitempty"`
	Hackerone       struct {
		Rank  int `json:"rank"`
		Count int `json:"count"`
	} `json:"hackerone,omitempty"`
	AgeInDays     int               `json:"age_in_days,omitempty"`
	VulnStatus    string            `json:"vuln_status,omitempty"`
	IsPoc         bool              `json:"is_poc"`
	IsRemote      bool              `json:"is_remote"`
	IsOss         bool              `json:"is_oss"`
	VulnerableCPE []string          `json:"vulnerable_cpe,omitempty"`
	Shodan        *OutputShodanData `json:"shodan,omitempty"`
	OSS           *OSS              `json:"oss,omitempty"`
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

type NucleiTemplates struct {
	TemplateIssue     string     `json:"template_issue,omitempty"`
	TemplateIssueType string     `json:"template_issue_type,omitempty"`
	TemplatePath      string     `json:"template_path,omitempty"`
	TemplatePR        string     `json:"template_pr,omitempty"`
	TemplateURL       string     `json:"template_url,omitempty"`
	CreatedAt         *time.Time `json:"created_at,omitempty"`
	UpdatedAt         *time.Time `json:"updated_at,omitempty"`
}

type OSS struct {
	AllLanguages  map[string]int `json:"all_languages,omitempty"`
	Description   string        `json:"description,omitempty"`
	Forks         int           `json:"forks,omitempty"`
	Language      string        `json:"language,omitempty"`
	Stars         int           `json:"stars,omitempty"`
	Subscribers   int           `json:"subscribers,omitempty"`
	Topics        []string      `json:"topics,omitempty"`
	PushedAt      CustomTime     `json:"pushed_at,omitempty"`
	CreatedAt     CustomTime     `json:"created_at,omitempty"`
	UpdatedAt     CustomTime     `json:"updated_at,omitempty"`
	URL           string        `json:"url,omitempty"`
}

type CustomTime struct {
	time.Time
}

func (ct *CustomTime) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" {
		return nil
	}
	t, err := time.Parse(`"2006-01-02 15:04:05 -0700 MST"`, s)
	if err != nil {
		return err
	}
	ct.Time = t
	return nil
}

type OutputCpe struct {
	Cpe      *string `json:"cpe,omitempty"`
	Vendor   *string `json:"vendor,omitempty"`
	Product  *string `json:"product,omitempty"`
	Platform *string `json:"framework,omitempty"`
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
