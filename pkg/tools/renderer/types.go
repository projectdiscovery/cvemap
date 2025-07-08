package renderer

import (
	"github.com/projectdiscovery/cvemap"
)

// LayoutLine represents a single line in the layout configuration
type LayoutLine struct {
	Line   int      `json:"line"`
	Format string   `json:"format"`
	OmitIf []string `json:"omit_if"`
}

// Entry represents a vulnerability entry with all fields needed for rendering
type Entry struct {
	DocID            string                `json:"doc_id"`
	Name             string                `json:"name"`
	Severity         string                `json:"severity"`
	Author           []string              `json:"author"`
	AgeInDays        int                   `json:"age_in_days"`
	EpssScore        float64               `json:"epss_score"`
	CvssScore        float64               `json:"cvss_score"`
	Exposure         *cvemap.VulnExposure  `json:"exposure"`
	AffectedProducts []*cvemap.ProductInfo `json:"affected_products"`
	IsPatchAvailable bool                  `json:"is_patch_available"`
	PocCount         int                   `json:"poc_count"`
	IsKev            bool                  `json:"is_kev"`
	Kev              []*cvemap.KevInfo     `json:"kev"`
	IsTemplate       bool                  `json:"is_template"`
	H1               *cvemap.H1Stats       `json:"h1"`
	Tags             []string              `json:"tags"`
	Pocs             []*cvemap.POC         `json:"pocs"`
	Citations        []*cvemap.Citation    `json:"citations"`
	Description      string                `json:"description"`
	Impact           string                `json:"impact"`
	Remediation      string                `json:"remediation"`
	TemplateURI      string                `json:"template_uri"`
	TemplateRaw      string                `json:"template_raw"`
}

// FromVulnerability converts a cvemap.Vulnerability to an Entry
func FromVulnerability(v *cvemap.Vulnerability) *Entry {
	if v == nil {
		return nil
	}

	entry := &Entry{
		DocID:            v.DocID,
		Name:             v.Name,
		Severity:         v.Severity,
		Author:           v.Author,
		AgeInDays:        v.AgeInDays,
		EpssScore:        v.EpssScore,
		CvssScore:        v.CvssScore,
		Exposure:         v.Exposure,
		AffectedProducts: v.AffectedProducts,
		IsPatchAvailable: v.IsPatchAvailable,
		PocCount:         v.PocCount,
		IsKev:            v.IsKev,
		Kev:              v.Kev,
		IsTemplate:       v.IsTemplate,
		H1:               v.H1,
		Tags:             v.Tags,
		Pocs:             v.Pocs,
		Citations:        v.Citations,
		Description:      v.Description,
		Impact:           v.Impact,
		Remediation:      v.Remediation,
		TemplateURI:      v.URI,
		TemplateRaw:      v.Raw,
	}

	return entry
}
