package ui

import (
	"strings"

	"github.com/derailed/tview"
	"github.com/derailed/tcell/v2"
)


type Splash struct {
	*tview.Flex
}

func NewSplash(version string) *Splash {
	s := Splash{Flex: tview.NewFlex()}
	s.SetBackgroundColor(tcell.ColorBlack)

	logo := tview.NewTextView()
	logo.SetDynamicColors(true)
	logo.SetTextAlign(tview.AlignCenter)
	s.layoutLogo(logo)

	vers := tview.NewTextView()
	vers.SetDynamicColors(true)
	vers.SetTextAlign(tview.AlignCenter)
	s.layoutRev(vers, version)

	s.SetDirection(tview.FlexRow)
	s.AddItem(tview.NewBox(), 10, 1, false)
	s.AddItem(logo, 10, 1, false)
	s.AddItem(vers, 10, 1, false)

	return &s
}

func (s *Splash) layoutLogo(t *tview.TextView) {
	logo := strings.Join(LogoBig, "\n")
	t.SetText(logo)
	t.SetTextColor(tcell.ColorWheat)
	t.SetBorderPadding(2, 0, 1, 1)
}

func (s *Splash) layoutRev(t *tview.TextView, rev string) {
	t.SetText(rev)
	t.SetTextColor(tcell.ColorSpringGreen)
}
