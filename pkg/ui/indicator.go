package ui

import (
	"github.com/derailed/tview"
	"github.com/derailed/tcell/v2"
)

type StatusIndicator struct {
	*tview.TextView

	app       *App
	permanent string
}

// NewStatusIndicator returns a new status indicator.
func NewStatusIndicator(app *App) *StatusIndicator {
	s := StatusIndicator{
		TextView: tview.NewTextView(),
		app:      app,
	}
	s.SetTextAlign(tview.AlignCenter)
	s.SetTextColor(tcell.ColorWhite)
	s.SetBackgroundColor(tcell.ColorBlack)
	s.SetDynamicColors(true)
	s.SetPermanent("")
	return &s
}

// SetPermanent sets permanent title to be reset to after updates.
func (s *StatusIndicator) SetPermanent(info string) {
	s.permanent = info
	s.SetText(info)
}
