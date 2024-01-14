package view

import (
	"github.com/derailed/tview"
	"github.com/derailed/tcell/v2"
)

type Tab struct {
	*App
	items []tview.Primitive
}

func NewTab(app *App) *Tab {
	t := Tab{App: app, items: []tview.Primitive{}}
	t.Add()
	return &t
}

func (t *Tab) Add() {
	
}

func (t *Tab) tabAction(event *tcell.EventKey) *tcell.EventKey {
	if t.InCmdMode() {
		return event
	}

	focusIdx := t.currentFocusIdx()

	if event.Key() == tcell.KeyTAB {
		if focusIdx+1 == len(t.items) {
			t.App.Application.SetFocus(t.Content.Pages.Current())
			return event
		}
		focusIdx = focusIdx + 1
	}
	if focusIdx < 0 {
		focusIdx = 0
	}
	t.App.Application.SetFocus(t.items[focusIdx])
	return event
}

func (t *Tab) currentFocusIdx() int {
	focusIdx := -1
	for i, p := range t.items {
		if p.HasFocus() {
			focusIdx = i
			break
		}
	}
	return focusIdx
}
