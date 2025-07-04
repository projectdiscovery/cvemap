// Package cvemap provides types for the /v2/vulnerability API client.
package cvemap

import (
	"time"
)

// Vulnerability represents a vulnerability object returned by the API.
// This struct is a flat composition of all fields from the OpenAPI Vulnerability schema.
// All fields have omitempty. No struct embedding is used.
type Vulnerability struct {
	// CVEInfo fields
	CVEID            string     `json:"cve_id,omitempty"`
	AgeInDays        int        `json:"age_in_days,omitempty"`
	Assignee         string     `json:"assignee,omitempty"`
	CveCreatedAt     *time.Time `json:"cve_created_at,omitempty"`
	CveUpdatedAt     *time.Time `json:"cve_updated_at,omitempty"`
	CvssMetrics      string     `json:"cvss_metrics,omitempty"`
	CvssScore        float64    `json:"cvss_score,omitempty"`
	EpssPercentile   float64    `json:"epss_percentile,omitempty"`
	EpssScore        float64    `json:"epss_score,omitempty"`
	IsAuth           bool       `json:"is_auth,omitempty"`
	IsKev            bool       `json:"is_kev,omitempty"`
	IsOss            bool       `json:"is_oss,omitempty"`
	IsPatchAvailable bool       `json:"is_patch_available,omitempty"`
	IsPoc            bool       `json:"is_poc,omitempty"`
	IsRemote         bool       `json:"is_remote,omitempty"`
	IsTemplate       bool       `json:"is_template,omitempty"`
	IsVkev           bool       `json:"is_vkev,omitempty"`
	Kev              []*KevInfo `json:"kev,omitempty"`
	PocCount         int        `json:"poc_count,omitempty"`
	PocFirstSeen     *time.Time `json:"poc_first_seen,omitempty"`
	Pocs             []*POC     `json:"pocs,omitempty"`
	VulnStatus       string     `json:"vuln_status,omitempty"`

	// VulnerabilityInfo extra fields
	Citations           []*Citation `json:"citations,omitempty"`
	Cwe                 []string    `json:"cwe,omitempty"`
	Description         string      `json:"description,omitempty"`
	Impact              string      `json:"impact,omitempty"`
	Name                string      `json:"name,omitempty"`
	Product             string      `json:"product,omitempty"`
	Remediation         string      `json:"remediation,omitempty"`
	RequirementType     string      `json:"requirement_type,omitempty"`
	Requirements        string      `json:"requirements,omitempty"`
	Severity            string      `json:"severity,omitempty"`
	TemplateCoverage    string      `json:"template_coverage,omitempty"`
	Vendor              string      `json:"vendor,omitempty"`
	VulnerabilityImpact []string    `json:"vulnerability_impact,omitempty"`
	VulnerabilityType   string      `json:"vulnerability_type,omitempty"`
	Weaknesses          []*Weakness `json:"weaknesses,omitempty"`

	// NucleiTemplate fields (flattened)
	// TemplateSourceMeta
	Category        string `json:"category,omitempty"`
	IntegrationID   string `json:"integration_id,omitempty"`
	IntegrationType string `json:"integration_type,omitempty"`
	PullRequest     string `json:"pull_request,omitempty"`
	Ref             string `json:"ref,omitempty"`
	ReleaseTag      string `json:"release_tag,omitempty"`
	Score           int    `json:"score,omitempty"`
	TemplateType    string `json:"template_type,omitempty"`

	// TemplateStatus
	IsDraft      bool `json:"is_draft,omitempty"`
	IsEarly      bool `json:"is_early,omitempty"`
	IsGithub     bool `json:"is_github,omitempty"`
	IsNew        bool `json:"is_new,omitempty"`
	IsPdresearch bool `json:"is_pdresearch,omitempty"`
	IsPdteam     bool `json:"is_pdteam,omitempty"`
	IsPdtemplate bool `json:"is_pdtemplate,omitempty"`

	// TemplateFileMeta
	Dir      string `json:"dir,omitempty"`
	Filename string `json:"filename,omitempty"`
	URI      string `json:"uri,omitempty"`

	// TemplateContent
	Author   []string       `json:"author,omitempty"`
	Digest   string         `json:"digest,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
	Raw      string         `json:"raw,omitempty" yaml:"nuclei_template,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
	Type     string         `json:"type,omitempty"`

	// TemplateSharingMetadata
	Organizations    []string   `json:"organizations,omitempty"`
	OriginTemplateID string     `json:"origin_template_id,omitempty"`
	ShareType        string     `json:"share_type,omitempty"`
	TTL              string     `json:"ttl,omitempty"`
	TTLFrom          *time.Time `json:"ttl_from,omitempty"`
	Users            []int      `json:"users,omitempty"`

	// NucleiTemplate extra fields
	AIMeta         *AIMeta         `json:"ai_meta,omitempty"`
	Classification *Classification `json:"classification,omitempty"`
	ID             string          `json:"id,omitempty"`
	UserID         int             `json:"user_id,omitempty"`

	// Vulnerability extra fields
	AffectedProducts []*ProductInfo `json:"affected_products,omitempty"`
	CreatedAt        *time.Time     `json:"created_at,omitempty"`
	DocID            string         `json:"doc_id,omitempty"`
	DocType          string         `json:"doc_type,omitempty"`
	Exposure         *VulnExposure  `json:"exposure,omitempty"`
	H1               *H1Stats       `json:"h1,omitempty"`
	NTPS             int            `json:"ntps,omitempty"`
	UpdatedAt        *time.Time     `json:"updated_at,omitempty"`
}

// Citation represents a citation for a vulnerability/template.
type Citation struct {
	AddedAt *time.Time `json:"added_at,omitempty"`
	Source  string     `json:"source,omitempty"`
	Tags    []string   `json:"tags,omitempty"`
	URL     string     `json:"url,omitempty"`
}

// KevInfo represents KEV (Known Exploited Vulnerabilities) info.
type KevInfo struct {
	AddedDate                  *time.Time `json:"added_date,omitempty"`
	DueDate                    *time.Time `json:"due_date,omitempty"`
	KnownRansomwareCampaignUse bool       `json:"known_ransomware_campaign_use,omitempty"`
	Source                     string     `json:"source,omitempty"`
}

// POC represents a proof of concept for a vulnerability.
type POC struct {
	AddedAt *time.Time `json:"added_at,omitempty"`
	Source  string     `json:"source,omitempty"`
	URL     string     `json:"url,omitempty"`
}

// Weakness represents a CWE weakness.
type Weakness struct {
	CweID   string `json:"cwe_id,omitempty"`
	CweName string `json:"cwe_name,omitempty"`
}

// ProductInfo represents affected product information.
type ProductInfo struct {
	Category        string         `json:"category,omitempty"`
	Cpe             []string       `json:"cpe,omitempty"`
	DeploymentModel string         `json:"deployment_model,omitempty"`
	Industry        string         `json:"industry,omitempty"`
	IsPd            bool           `json:"is_pd,omitempty"`
	Product         string         `json:"product,omitempty"`
	ProjectRepos    map[string]any `json:"project_repos,omitempty"`
	Projects        []string       `json:"projects,omitempty"`
	Summary         string         `json:"summary,omitempty"`
	TechDomain      string         `json:"tech_domain,omitempty"`
	Vendor          string         `json:"vendor,omitempty"`
}

// VulnExposure represents exposure stats for a vulnerability.
type VulnExposure struct {
	MaxHosts int              `json:"max_hosts,omitempty"`
	MinHosts int              `json:"min_hosts,omitempty"`
	Values   []*ExposureStats `json:"values,omitempty"`
}

// ExposureStats represents search engine stats for a product.
type ExposureStats struct {
	Fofa     *SearchEngineStats `json:"fofa,omitempty"`
	ID       string             `json:"id,omitempty"`
	MaxHosts int                `json:"max_hosts,omitempty"`
	MinHosts int                `json:"min_hosts,omitempty"`
	Shodan   *SearchEngineStats `json:"shodan,omitempty"`
}

// SearchEngineStats represents stats from a search engine.
type SearchEngineStats struct {
	MaxHosts int      `json:"max_hosts,omitempty"`
	MinHosts int      `json:"min_hosts,omitempty"`
	Queries  []string `json:"queries,omitempty"`
}

// H1Stats represents HackerOne stats for a vulnerability.
type H1Stats struct {
	DeltaRank    int `json:"delta_rank,omitempty"`
	DeltaReports int `json:"delta_reports,omitempty"`
	Rank         int `json:"rank,omitempty"`
	Reports      int `json:"reports,omitempty"`
}

// AIMeta represents AI metadata for a template.
type AIMeta struct {
	IsPromptByHuman   bool   `json:"is_prompt_by_human,omitempty"`
	IsTemplateByHuman bool   `json:"is_template_by_human,omitempty"`
	ModelUsed         string `json:"model_used,omitempty"`
	Prompt            string `json:"prompt,omitempty"`
}

// Classification represents classification metadata for a template.
type Classification struct {
	Cpe            string   `json:"cpe,omitempty"`
	CveID          []string `json:"cve_id,omitempty"`
	CvssMetrics    string   `json:"cvss_metrics,omitempty"`
	CvssScore      float64  `json:"cvss_score,omitempty"`
	CweID          []string `json:"cwe_id,omitempty"`
	EpssPercentile float64  `json:"epss_percentile,omitempty"`
	EpssScore      float64  `json:"epss_score,omitempty"`
}

// Schema represents schema information for a template.
type Schema struct {
	Version string `json:"version,omitempty"`
}

// SearchParams defines query parameters for vulnerability search.
type SearchParams struct {
	Limit       *int     `json:"limit,omitempty"`
	Offset      *int     `json:"offset,omitempty"`
	SortAsc     *string  `json:"sort_asc,omitempty"`
	SortDesc    *string  `json:"sort_desc,omitempty"`
	Fields      []string `json:"fields,omitempty"`
	TermFacets  []string `json:"term_facets,omitempty"`
	RangeFacets []string `json:"range_facets,omitempty"`
	Query       *string  `json:"q,omitempty"`
	Highlight   *bool    `json:"highlight,omitempty"`
	FacetSize   *int     `json:"facet_size,omitempty"`
}

// SearchResponse represents the response from /v2/vulnerability/search.
type SearchResponse struct {
	Count   int             `json:"count"`
	Facets  map[string]any  `json:"facets,omitempty"`
	Results []Vulnerability `json:"results"`
	Total   int             `json:"total"`
}

// GetByIDParams defines optional query parameters for GetVulnerabilityByID.
type GetByIDParams struct {
	Fields []string `json:"fields,omitempty"`
}

// VulnerabilityResponse represents the response from /v2/vulnerability/{id}.
type VulnerabilityResponse struct {
	Data *Vulnerability `json:"data"`
}

// VulnerabilityFilter describes a filter field for vulnerabilities.
type VulnerabilityFilter struct {
	CanSort        bool     `json:"can_sort"`
	DataType       string   `json:"data_type"`
	Description    string   `json:"description"`
	Examples       []string `json:"examples"`
	FacetPossible  bool     `json:"facet_possible"`
	Field          string   `json:"field"`
	SearchAnalyzer string   `json:"search_analyzer"`
	EnumValues     []string `json:"enum_values"`
}

// Ptr is a helper function to create a pointer to a value
// Simple yet useful
func Ptr[T any](v T) *T {
	return &v
}
