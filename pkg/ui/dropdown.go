package ui

import (
	"fmt"

	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
)

const DropDownIndicatiorColor string = "green"

type DropDown struct {
	*tview.DropDown
	label   string
	options []string
}

func NewDropDown(label string, options []string) *DropDown {
	d := DropDown{
		DropDown: tview.NewDropDown(),
		label:    label,
		options:  options,
	}
	d.build()
	return &d
}

func (d *DropDown) SetSelectedFn(selectedFn DropdownSelectedFn) {
	d.SetSelectedFunc(func(text string, index int) {
		selectedFn(text, index)
	})
}

func (d *DropDown) build() {
	d.SetLabel(fmt.Sprintf("[%s::b]%s", "orange", d.label))
	d.SetOptions(d.options, func(text string, index int) {})
	d.SetCurrentOption(0)
	d.SetBorderPadding(0, 0, 0, 0)
	d.SetTextOptions("  ", " ", fmt.Sprintf("[%s::bd]▽[-:-:-] ", DropDownIndicatiorColor), "", "")
	d.SetFieldBackgroundColor(tcell.ColorBlack.TrueColor())
	d.SetFieldTextColor(tcell.ColorAntiqueWhite.TrueColor())
}
