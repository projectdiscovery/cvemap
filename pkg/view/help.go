package view

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/projectdiscovery/cvemap/pkg/model"
	"github.com/projectdiscovery/cvemap/pkg/ui"
)

const (
	helpTitle    = "Help"
	helpTitleFmt = " [aqua::b]%s "
)

// HelpFunc processes menu hints.
type HelpFunc func() model.MenuHints

// Help presents a help viewer.
type Help struct {
	*Table
	hints           HelpFunc
	maxRows         int
	// maxKey, maxDesc int
}

// NewHelp returns a new help viewer.
func NewHelp(app *App) *Help {
	return &Help{
		Table: NewTable("help"),
		hints: app.Content.Top().Hints,
	}
}

// Init initializes the component.
func (h *Help) Init(ctx context.Context) error {
	if err := h.Table.Init(ctx); err != nil {
		return err
	}
	h.SetSelectable(false, false)
	h.resetTitle()
	h.SetBorder(true)
	h.SetBorderPadding(0, 0, 1, 1)
	h.bindKeys()
	h.build()
	return nil
}

func (h *Help) bindKeys() {
	h.Actions().Delete(ui.KeySpace, tcell.KeyCtrlSpace, tcell.KeyCtrlS, ui.KeySlash)
	h.Actions().Set(ui.KeyActions{
		tcell.KeyEscape: ui.NewKeyAction("Back", h.app.PrevCmd, true),
	})
}

func (h *Help) build() {
	h.Clear()

	sections := []string{"SERVICES", "GENERAL", "NAVIGATION"}
	h.maxRows = len(h.showGeneral())
	ff := []HelpFunc{
		h.showServices,
		h.hints,
		h.showGeneral,
	}

	var col int
	for i, section := range sections {
		hh := ff[i]()
		sort.Sort(hh)

		h.addSection(col, section, hh)

		col += 2
	}
}

func (h *Help) showServices() model.MenuHints {
	return model.MenuHints{
		{
			Mnemonic:    "cvemap",
			Description: "View cvemap screen",
		},
	}

}

func (h *Help) showGeneral() model.MenuHints {
	return model.MenuHints{
		{
			Mnemonic:    "?",
			Description: "Help",
		},
		{
			Mnemonic:    "esc",
			Description: "Back/Clear",
		},
		{
			Mnemonic:    "tab",
			Description: "toggle dropdown",
		},
		{
			Mnemonic:    "Ctrl-u",
			Description: "Command Clear",
		},
		{
			Mnemonic:    "Ctrl-e",
			Description: "Toggle Header",
		},

		{
			Mnemonic:    ":q",
			Description: "Quit",
		},
		{
			Mnemonic:    "z",
			Description: "Import as csv",
		},
		{
			Mnemonic:    "g",
			Description: "Goto Top",
		},
		{
			Mnemonic:    "Shift-g",
			Description: "Goto Bottom",
		},
		{
			Mnemonic:    "Ctrl-b",
			Description: "Page Up",
		},
		{
			Mnemonic:    "Ctrl-f",
			Description: "Page Down",
		},
		{
			Mnemonic:    "h",
			Description: "Left",
		},
		{
			Mnemonic:    "l",
			Description: "Right",
		},
		{
			Mnemonic:    "k",
			Description: "Up",
		},
		{
			Mnemonic:    "j",
			Description: "Down",
		},
	}
}

func (h *Help) resetTitle() {
	h.SetTitle(fmt.Sprintf(helpTitleFmt, helpTitle))
}

func (h *Help) addSpacer(c int) {
	//logic to add space
}

func (h *Help) addSection(c int, title string, hh model.MenuHints) {
	if len(hh) > h.maxRows {
		h.maxRows = len(hh)
	}
	row := 0
	h.SetCell(row, c, h.titleCell(title).SetTextColor(tcell.ColorSpringGreen))
	h.addSpacer(c + 1)
	row++

	for _, hint := range hh {
		col := c
		h.SetCell(row, col, tview.NewTableCell(toMnemonic(hint.Mnemonic)).SetTextColor(tcell.ColorDodgerBlue))
		col++
		h.SetCell(row, col, tview.NewTableCell(hint.Description).SetTextColor(tcell.ColorPapayaWhip))
		row++
	}

	if len(hh) >= h.maxRows {
		return
	}
}

// ----------------------------------------------------------------------------
// Helpers...

func toMnemonic(s string) string {
	if len(s) == 0 {
		return s
	}

	return "<" + keyConv(strings.ToLower(s)) + ">"
}

func keyConv(s string) string {
	if !strings.Contains(s, "alt") {
		return s
	}

	if runtime.GOOS != "darwin" {
		return s
	}

	return strings.Replace(s, "alt", "opt", 1)
}

func (h *Help) titleCell(title string) *tview.TableCell {
	c := tview.NewTableCell(title)
	c.SetAttributes(tcell.AttrBold)
	c.SetExpansion(1)
	c.SetAlign(tview.AlignLeft)

	return c
}
