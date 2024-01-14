package ui

import (
	"strings"

	"github.com/derailed/tview"
	"github.com/derailed/tcell/v2"
)

const DropdownPadSpaces int = 3

type Info struct {
	*tview.Flex
	items map[string]tview.Primitive
}

func NewInfo(items map[string]tview.Primitive) *Info {
	i := Info{
		Flex:  tview.NewFlex(),
		items: items,
	}
	i.padDropDownLabels()
	i.build()
	return &i
}

func (i *Info) padDropDownLabels() {
	maxLabelLen := 0
	maxOptionLen := 0
	for _, p := range i.items {
		d, ok := p.(*DropDown)
		if ok {
			if len(d.GetLabel()) > maxLabelLen {
				maxLabelLen = len(d.GetLabel())
			}
			if d.GetFieldWidth() > maxOptionLen {
				maxOptionLen = d.GetFieldWidth()
			}
		}
	}

	for _, p := range i.items {
		d, ok := p.(*DropDown)
		if ok {
			d.SetFieldWidth(maxOptionLen + DropdownPadSpaces)
			d.SetLabel(d.GetLabel() + strings.Repeat(" ", (maxLabelLen-len(d.GetLabel()))+1))
		}
	}
}

func (i *Info) build() {
	i.Clear()
	i.SetDirection(tview.FlexRow)
	i.SetBorderColor(tcell.ColorBlack.TrueColor())
	i.SetBorderPadding(0, 4, 1, 1)
	for _, k := range SortMapKeys(i.items) {
		i.AddItem(i.items[k], 0, 1, false)
	}
}
