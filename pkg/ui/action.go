package ui

import (
	"sort"

	"github.com/derailed/tcell/v2"
	"github.com/projectdiscovery/cvemap/pkg/model"
	"github.com/projectdiscovery/gologger"
)

type (
	// ActionHandler handles a keyboard command.
	ActionHandler func(*tcell.EventKey) *tcell.EventKey

	// KeyAction represents a keyboard action.
	KeyAction struct {
		Description string
		Action      ActionHandler
		Visible     bool
		Shared      bool
	}

	// KeyActions tracks mappings between keystrokes and actions.
	KeyActions map[tcell.Key]KeyAction
)

// NewKeyAction returns a new keyboard action.
func NewKeyAction(d string, a ActionHandler, display bool) KeyAction {
	return KeyAction{Description: d, Action: a, Visible: display}
}

// NewSharedKeyAction returns a new shared keyboard action.
func NewSharedKeyAction(d string, a ActionHandler, display bool) KeyAction {
	return KeyAction{Description: d, Action: a, Visible: display, Shared: true}
}

// Add sets up keyboard action listener.
func (a KeyActions) Add(aa KeyActions) {
	for k, v := range aa {
		a[k] = v
	}
}

// Clear remove all actions.
func (a KeyActions) Clear() {
	for k := range a {
		delete(a, k)
	}
}

// Set replace actions with new ones.
func (a KeyActions) Set(aa KeyActions) {
	for k, v := range aa {
		a[k] = v
	}
}

// Hints returns a collection of hints.
func (a KeyActions) Hints() model.MenuHints {
	kk := make([]int, 0, len(a))
	for k := range a {
		if !a[k].Shared {
			kk = append(kk, int(k))
		}
	}
	sort.Ints(kk)

	hh := make(model.MenuHints, 0, len(kk))
	for _, k := range kk {
		if name, ok := tcell.KeyNames[tcell.Key(int16(k))]; ok {
			hh = append(hh,
				model.MenuHint{
					Mnemonic:    name,
					Description: a[tcell.Key(k)].Description,
					Visible:     a[tcell.Key(k)].Visible,
				},
			)
		} else {
			gologger.Error().Msgf("Unable to locate KeyName for %#v", k)
		}
	}
	return hh
}

// Delete deletes actions by the given keys.
func (a KeyActions) Delete(kk ...tcell.Key) {
	for _, k := range kk {
		delete(a, k)
	}
}
