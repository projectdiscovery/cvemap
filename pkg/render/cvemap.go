package render

import (
	"fmt"

	"github.com/derailed/tview"
	"github.com/projectdiscovery/cvemap/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
)

type Cvemap struct {
}

// Header returns a header row.
func (cvemap Cvemap) Header() Header {
	return Header{
		HeaderColumn{Name: "ID", SortIndicatorIdx: 0, Align: tview.AlignLeft, Hide: false, Wide: false, MX: false, Time: false},
		HeaderColumn{Name: "CVSS", SortIndicatorIdx: 1, Align: tview.AlignLeft, Hide: false, Wide: false, MX: false, Time: false},
		HeaderColumn{Name: "Severity", SortIndicatorIdx: 0, Align: tview.AlignLeft, Hide: false, Wide: false, MX: false, Time: false},
		HeaderColumn{Name: "EPSS", SortIndicatorIdx: 0, Align: tview.AlignLeft, Hide: false, Wide: false, MX: false, Time: false},
		HeaderColumn{Name: "Product", SortIndicatorIdx: 0, Align: tview.AlignLeft, Hide: false, Wide: true, MX: false, Time: true},
		HeaderColumn{Name: "Vendor", SortIndicatorIdx: -1, Align: tview.AlignLeft, Hide: false, Wide: true, MX: false, Time: true},
		HeaderColumn{Name: "Age", SortIndicatorIdx: 0, Align: tview.AlignLeft, Hide: false, Wide: false, MX: false, Time: false},
		HeaderColumn{Name: "Poc", SortIndicatorIdx: -1, Align: tview.AlignLeft, Hide: false, Wide: false, MX: false, Time: false},
		HeaderColumn{Name: "Template", SortIndicatorIdx: -1, Align: tview.AlignCenter, Hide: false, Wide: false, MX: false, Time: false},
	}
}

func (cvemap Cvemap) Render(o interface{}, ns string, row *Row) error {
	cve, ok := o.(types.CVEData)

	if !ok {
		return errorutil.New("expected CVEData, but got %T", o)
	}

	row.ID = ns

	product := ""
	if cve.Cpe != nil && cve.Cpe.Product != nil {
		product = *cve.Cpe.Product
	}
	vendor := ""
	if cve.Cpe != nil && cve.Cpe.Vendor != nil {
		vendor = *cve.Cpe.Vendor
	}

	hasTemplate := ""
	if cve.IsTemplate {
		hasTemplate = "✅"
	} else {
		hasTemplate = "❌"
	}

	row.Fields = Fields{
		cve.CveID,
		fmt.Sprintf("%v", cve.CvssScore),
		cve.Severity,
		fmt.Sprintf("%v", cve.Epss.Score),
		product,
		vendor,
		fmt.Sprintf("%v", cve.AgeInDays),
		fmt.Sprintf("%v", cve.IsPoc),
		fmt.Sprintf("%v", hasTemplate),
	}

	return nil
}
