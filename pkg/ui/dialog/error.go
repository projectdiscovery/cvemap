package dialog

import (
	"fmt"
	"strings"

	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/projectdiscovery/cvemap/pkg/ui"
)

// ShowConfirm pops a confirmation dialog.
func ShowError(pages *ui.Pages, msg string) {
	f := tview.NewForm()
	f.SetItemPadding(0)
	f.SetButtonsAlign(tview.AlignCenter).
		SetButtonBackgroundColor(tcell.ColorDarkSlateBlue).
		SetButtonTextColor(tcell.ColorBlack.TrueColor()).
		SetLabelColor(tcell.ColorWhite.TrueColor()).
		SetFieldTextColor(tcell.ColorIndianRed)
	f.AddButton("Dismiss", func() {
		dismissError(pages)
	})
	if b := f.GetButton(0); b != nil {
		b.SetBackgroundColorActivated(tcell.ColorDodgerBlue)
		b.SetLabelColorActivated(tcell.ColorBlack.TrueColor())
	}
	f.SetFocus(0)
	modal := tview.NewModalForm("<error>", f)
	modal.SetText(cowTalk(msg))
	modal.SetTextColor(tcell.ColorOrangeRed)
	modal.SetBackgroundColor(tcell.ColorBlack.TrueColor())
	modal.SetBorderColor(tcell.ColorBlue)
	modal.SetDoneFunc(func(int, string) {
		dismissError(pages)
	})
	pages.AddPage(confirmKey, modal, false, false)
	pages.ShowPage(confirmKey)
}

func dismissError(pages *ui.Pages) {
	pages.RemovePage(confirmKey)
}

func cowTalk(says string) string {
	msg := fmt.Sprintf("< Ruroh? %s >", says)
	buff := make([]string, 0, len(cow)+3)
	buff = append(buff, msg)
	buff = append(buff, cow...)

	return strings.Join(buff, "\n")
}

var cow = []string{
	`\   ^__^            `,
	` \  (oo)\_______    `,
	`    (__)\       )\/\`,
	`        ||----w |   `,
	`        ||     ||   `,
}
