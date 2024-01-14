package ui

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/derailed/tview"
	"github.com/projectdiscovery/cvemap/pkg/model"
)

const (
	maxRows = 6
)

var menuRX = regexp.MustCompile(`\d`)

// Menu presents menu options.
type Menu struct {
	*tview.Table
}

// NewMenu returns a new menu.
func NewMenu() *Menu {
	m := Menu{
		Table: tview.NewTable(),
	}
	return &m
}

// StackPushed notifies a component was added.
func (m *Menu) StackPushed(c model.Component) {
	m.HydrateMenu(c.Hints())
}

// StackPopped notifies a component was removed.
func (m *Menu) StackPopped(o, top model.Component) {
	if top != nil {
		m.HydrateMenu(top.Hints())
	} else {
		m.Clear()
	}
}

// StackTop notifies the top component.
func (m *Menu) StackTop(t model.Component) {
	m.HydrateMenu(t.Hints())
}

// HydrateMenu populate menu ui from hints.
func (m *Menu) HydrateMenu(hh model.MenuHints) {
	m.Clear()
	sort.Sort(hh)

	table := make([]model.MenuHints, maxRows+1)
	colCount := (len(hh) / maxRows) + 1
	if m.hasDigits(hh) {
		colCount++
	}
	for row := 0; row < maxRows; row++ {
		table[row] = make(model.MenuHints, colCount)
	}
	t := m.buildMenuTable(hh, table, colCount)

	for row := 0; row < len(t); row++ {
		for col := 0; col < len(t[row]); col++ {
			c := tview.NewTableCell(t[row][col])
			if len(t[row][col]) == 0 {
				c = tview.NewTableCell("")
			}
			m.SetCell(row, col, c)
		}
	}
}

func (m *Menu) hasDigits(hh model.MenuHints) bool {
	for _, h := range hh {
		if !h.Visible {
			continue
		}
		if menuRX.MatchString(h.Mnemonic) {
			return true
		}
	}
	return false
}

func (m *Menu) buildMenuTable(hh model.MenuHints, table []model.MenuHints, colCount int) [][]string {
	var row, col int
	firstCmd := true
	maxKeys := make([]int, colCount)
	for _, h := range hh {
		if !h.Visible {
			continue
		}

		if !menuRX.MatchString(h.Mnemonic) && firstCmd {
			row, col, firstCmd = 0, col+1, false
			if table[0][0].IsBlank() {
				col = 0
			}
		}
		if maxKeys[col] < len(h.Mnemonic) {
			maxKeys[col] = len(h.Mnemonic)
		}
		table[row][col] = h
		row++
		if row >= maxRows {
			row, col = 0, col+1
		}
	}

	out := make([][]string, len(table))
	for r := range out {
		out[r] = make([]string, len(table[r]))
	}
	m.layout(table, maxKeys, out)

	return out
}

func (m *Menu) layout(table []model.MenuHints, mm []int, out [][]string) {
	for r := range table {
		for c := range table[r] {
			out[r][c] = m.formatMenu(table[r][c], mm[c])
		}
	}
}

func (m *Menu) formatMenu(h model.MenuHint, size int) string {
	if h.Mnemonic == "" || h.Description == "" {
		return ""
	}
	i, err := strconv.Atoi(h.Mnemonic)
	if err == nil {
		return formatNSMenu(i, h.Description)
	}

	return formatPlainMenu(h, size)
}

func toMnemonic(s string) string {
	if len(s) == 0 {
		return s
	}

	return "<" + strings.ToLower(s) + ">"
}

func formatNSMenu(i int, name string) string {
	return fmt.Sprintf("[pink::b]<%d>[white::bd] %s", i, name)
}

func formatPlainMenu(h model.MenuHint, size int) string {
	//#1E90FF hex for dodgerblue
	famt := "[#1E90FF::b]%" + strconv.Itoa(size+2) + "s[white::bd] %s"
	return fmt.Sprintf(famt, toMnemonic(h.Mnemonic), h.Description)
}
