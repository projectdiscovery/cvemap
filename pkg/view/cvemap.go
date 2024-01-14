package view

import (
	"github.com/derailed/tcell/v2"
	"github.com/projectdiscovery/cvemap/pkg/model"
	"github.com/projectdiscovery/cvemap/pkg/ui"
	"github.com/projectdiscovery/gologger"
)

type Cvemap struct {
	ResourceViewer
}

// NewCvemap returns a new viewer.
func NewCvemap(resource string) ResourceViewer {
	var e Cvemap
	e.ResourceViewer = NewBrowser(resource)
	e.AddBindKeysFn(e.bindKeys)
	return &e
}

func (cve *Cvemap) bindKeys(aa ui.KeyActions) {
	aa.Add(ui.KeyActions{
		ui.KeyShiftI:    ui.NewKeyAction("SortBy CveId", cve.GetTable().SortColCmd("ID", true), true),
		ui.KeyShiftS:    ui.NewKeyAction("SortBy Severity", cve.GetTable().SortColCmd("Severity", true), true),
		ui.KeyShiftV:    ui.NewKeyAction("SortBy Cvss", cve.GetTable().SortColCmd("CVSS", true), true),
		ui.KeyShiftE:    ui.NewKeyAction("SortBy Epss", cve.GetTable().SortColCmd("EPSS", true), true),
		ui.KeyShiftP:    ui.NewKeyAction("SortBy Product", cve.GetTable().SortColCmd("Product", true), true),
		ui.KeyShiftA:    ui.NewKeyAction("SortBy Age", cve.GetTable().SortColCmd("Age", true), true),
		tcell.KeyEscape: ui.NewKeyAction("Back", cve.App().PrevCmd, false),
		tcell.KeyEnter:  ui.NewKeyAction("View", cve.enterCmd, false),
	})
}

// func (cve *Cvemap) refreshCmd(evt *tcell.EventKey) *tcell.EventKey {
// 	ctx := cve.App().GetContext()
// 	ctx = context.WithValue(ctx, constant.KeySearchString, "jira")
// 	cve.App().Flash().Info("Refresing started...")
// 	err := cve.GetTable().GetModel().Refresh(ctx)
// 	cve.GetTable().Update(cve.GetTable().GetModel().Peek())
// 	gologger.Info().Msgf("Refresh err %v", err)
// 	cve.App().Flash().Info("Refresing done...")
// 	return nil
// }

func (cve *Cvemap) enterCmd(evt *tcell.EventKey) *tcell.EventKey {
	instanceId := cve.GetTable().GetSelectedItem()
	if instanceId != "" {
		f := describeResource
		if cve.GetTable().enterFn != nil {
			f = cve.GetTable().enterFn
		}
		f(cve.App(), cve.GetTable().GetModel(), cve.Resource(), instanceId)
		cve.App().Flash().Info("cve-id :" + instanceId)
	}

	return nil
}

// BufferCompleted indicates input was accepted.
func (cve *Cvemap) BufferCompleted(text, suggestion string) {
	gologger.Debug().Msgf("(cve *Cvemap) Buffer completed %s %s", text, suggestion)
}

// BufferChanged indicates the buffer was changed.
func (cve *Cvemap) BufferChanged(text, suggestion string) {
}

// BufferActive indicates the buff activity changed.
func (cve *Cvemap) BufferActive(state bool, kind model.BufferKind) {
	gologger.Debug().Msgf("(cve *Cvemap) Buffer active %v %v", state, kind)
}
