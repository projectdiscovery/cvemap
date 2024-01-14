package ui

import (
	"strings"

	"github.com/derailed/tview"
	"github.com/derailed/tcell/v2"
)

var LogoSmall = []string{
	" _____  _____ __ _ ___ ____ 	",
	"/ __| |/ / -_/  ' / _ `/ _ \\	",
	"\\__/|___/\\__/_/_/_\\_,_/ .__/",
	"                     /_/    	",
}

// LogoBig cls big logo for splash page.
var LogoBig = []string{
	" ██████ ██    ██ ███████ ███    ███  █████  ██████  ",
	"██      ██    ██ ██      ████  ████ ██   ██ ██   ██ ",
	"██      ██    ██ █████   ██ ████ ██ ███████ ██████  ",
	"██       ██  ██  ██      ██  ██  ██ ██   ██ ██      ",
	" ██████   ████   ███████ ██      ██ ██   ██ ██      ",
}

type Logo struct {
	*tview.Flex
	logo *tview.TextView
}

func NewLogo() *Logo {
	l := Logo{
		Flex: tview.NewFlex(),
		logo: tview.NewTextView(),
	}
	l.SetDirection(tview.FlexRow)
	l.buildLogo()
	l.AddItem(l.logo, 6, 1, false)
	return &l
}

func (l *Logo) buildLogo() {
	l.logo.SetText(strings.Join(LogoSmall, "\n"))
	l.logo.SetTextColor(tcell.ColorOrange)
}
