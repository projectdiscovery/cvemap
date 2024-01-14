package ui

import (
	"context"
	"os"
	"sync"

	"github.com/derailed/tcell/v2"
	"github.com/derailed/tview"
	"github.com/projectdiscovery/cvemap/pkg/constant"
	"github.com/projectdiscovery/cvemap/pkg/model"
)

type App struct {
	*tview.Application
	context context.Context
	Main    *Pages
	flash   *model.Flash
	actions KeyActions
	views   map[string]tview.Primitive
	cmdBuff *model.FishBuff
	running bool
	mx      sync.RWMutex
}

func NewApp() *App {
	a := App{
		Application: tview.NewApplication(),
		actions:     make(KeyActions),
		Main:        NewPages(),
		views:       make(map[string]tview.Primitive),
		flash:       model.NewFlash(model.DefaultFlashDelay),
		cmdBuff:     model.NewFishBuff(':', model.CommandBuffer),
	}
	a.views = map[string]tview.Primitive{
		"menu":   NewMenu(),
		"prompt": NewPrompt(&a, false),
		// "crumbs": NewCrumbs(),
	}
	return &a
}

func (a *App) Init() {
	a.bindKeys()
	a.Prompt().SetModel(a.cmdBuff)
	a.cmdBuff.AddListener(a)
	a.SetRoot(a.Main, true).EnableMouse(true)
}

// QueueUpdate queues up a ui action.
func (a *App) QueueUpdate(f func()) {
	if a.Application == nil {
		return
	}
	go func() {
		a.Application.QueueUpdate(f)
	}()
}

// QueueUpdateDraw queues up a ui action and redraw the ui.
func (a *App) QueueUpdateDraw(f func()) {
	if a.Application == nil {
		return
	}
	go func() {
		a.Application.QueueUpdateDraw(f)
	}()
}

// IsRunning checks if app is actually running.
func (a *App) IsRunning() bool {
	a.mx.RLock()
	defer a.mx.RUnlock()
	return a.running
}

// SetRunning sets the app run state.
func (a *App) SetRunning(f bool) {
	a.mx.Lock()
	defer a.mx.Unlock()
	a.running = f
}

// BufferCompleted indicates input was accepted.
func (a *App) BufferCompleted(text, suggestion string) {
	
}

// BufferChanged indicates the buffer was changed.
func (a *App) BufferChanged(text, suggestion string) {
}

// BufferActive indicates the buff activity changed.
func (a *App) BufferActive(state bool, kind model.BufferKind) {
	flex, ok := a.Main.GetPrimitive(constant.LowercaseCvemap).(*tview.Flex)
	if !ok {
		return
	}

	if state && flex.ItemAt(1) != a.Prompt() {
		flex.AddItemAtIndex(1, a.Prompt(), 3, 1, false)
	} else if !state && flex.ItemAt(1) == a.Prompt() {
		flex.RemoveItemAtIndex(1)
		a.SetFocus(flex)
	}
}

// SuggestionChanged notifies of update to command suggestions.
func (a *App) SuggestionChanged(ss []string) {}

// HasAction checks if key matches a registered binding.
func (a *App) HasAction(key tcell.Key) (KeyAction, bool) {
	act, ok := a.actions[key]
	return act, ok
}

// GetActions returns a collection of actions.
func (a *App) GetActions() KeyActions {
	return a.actions
}

func (a *App) UpdateContext(ctx context.Context) {
	a.context = ctx
}

// AddActions returns the application actions.
func (a *App) AddActions(aa KeyActions) {
	for k, v := range aa {
		a.actions[k] = v
	}
}

func (a *App) bindKeys() {
	a.actions = KeyActions{
		KeyColon:       NewKeyAction("Cmd", a.activateCmd, true),
		tcell.KeyCtrlR: NewKeyAction("Redraw", a.redrawCmd, false),
		tcell.KeyCtrlC: NewKeyAction("Quit", a.quitCmd, false),
		tcell.KeyCtrlU: NewSharedKeyAction("Clear Filter", a.clearCmd, false),
		tcell.KeyCtrlQ: NewSharedKeyAction("Clear Filter", a.clearCmd, false),
	}
}

// ResetPrompt reset the prompt model and marks buffer as active.
func (a *App) ResetPrompt(m PromptModel) {
	a.Prompt().SetModel(m)
	a.SetFocus(a.Prompt())
	m.SetActive(true)
}

// InCmdMode check if command mode is active.
func (a *App) InCmdMode() bool {
	return a.Prompt().InCmdMode()
}

// ResetCmd clear out user command.
func (a *App) ResetCmd() {
	a.cmdBuff.Reset()
}

// GetCmd retrieves user command.
func (a *App) GetCmd() string {
	return a.cmdBuff.GetText()
}

// CmdBuff returns the app cmd model.
func (a *App) CmdBuff() *model.FishBuff {
	return a.cmdBuff
}

// HasCmd check if cmd buffer is active and has a command.
func (a *App) HasCmd() bool {
	return a.cmdBuff.IsActive() && !a.cmdBuff.Empty()
}

// RedrawCmd forces a redraw.
func (a *App) redrawCmd(evt *tcell.EventKey) *tcell.EventKey {
	a.QueueUpdateDraw(func() {})
	return evt
}

func (a *App) quitCmd(evt *tcell.EventKey) *tcell.EventKey {
	a.BailOut()
	// overwrite the default ctrl-c behavior of tview
	return nil
}

// BailOut exits the application.
func (a *App) BailOut() {
	a.Stop()
	os.Exit(0)
}

// Views return the application root views.
func (a *App) Views() map[string]tview.Primitive {
	return a.views
}

func (a *App) clearCmd(evt *tcell.EventKey) *tcell.EventKey {
	if !a.cmdBuff.IsActive() {
		return evt
	}
	a.cmdBuff.ClearText(true)

	return nil
}

func (a *App) activateCmd(evt *tcell.EventKey) *tcell.EventKey {
	if a.InCmdMode() {
		return evt
	}
	a.ResetPrompt(a.cmdBuff)
	a.cmdBuff.ClearText(true)

	return nil
}

// View Accessors...

// Prompt returns command prompt.
func (a *App) Prompt() *Prompt {
	return a.views["prompt"].(*Prompt)
}

// Menu returns app menu.
func (a *App) Menu() *Menu {
	return a.views["menu"].(*Menu)
}

// TODO: remove
func (a *App) FlashView() *Flash {
	return a.views["flash"].(*Flash)
}

// Flash returns a flash model.
func (a *App) Flash() *model.Flash {
	return a.flash
}

// ----------------------------------------------------------------------------
// Helpers...

// AsKey converts rune to keyboard key.,.
func AsKey(evt *tcell.EventKey) tcell.Key {
	if evt.Key() != tcell.KeyRune {
		return evt.Key()
	}
	key := tcell.Key(evt.Rune())
	if evt.Modifiers() == tcell.ModAlt {
		key = tcell.Key(int16(evt.Rune()) * int16(evt.Modifiers()))
	}
	return key
}
