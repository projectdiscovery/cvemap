package view

import (
	"context"
	"sync"

	"github.com/derailed/tcell/v2"
	"github.com/projectdiscovery/cvemap/pkg/ui"
	"github.com/projectdiscovery/gologger"
)

// Browser represents a generic resource browser.
type Browser struct {
	*Table
	contextFn ContextFunc
	cancelFn  context.CancelFunc
	mx        sync.RWMutex ``
}

// NewBrowser returns a new browser.
func NewBrowser(resource string) ResourceViewer {
	return &Browser{
		Table: NewTable(resource),
	}
}

// Init watches all running pods in given namespace.
func (b *Browser) Init(ctx context.Context) error {
	if err := b.Table.Init(ctx); err != nil {
		return err
	}
	b.SetContextFn(func(c context.Context) context.Context {
		return ctx
	})
	b.bindKeys(b.Actions())
	for _, f := range b.bindKeysFn {
		f(b.Actions())
	}

	row, _ := b.GetSelection()
	if row == 0 && b.GetRowCount() > 0 {
		b.Select(1, 0)
	}
	b.GetModel().SetRefreshRate(DefaultRefreshRate)
	return nil
}

func (b *Browser) bindKeys(aa ui.KeyActions) {
	aa.Add(ui.KeyActions{
		ui.KeyR:       ui.NewSharedKeyAction("Filter Reset", b.resetCmd, false),
		tcell.KeyHelp: ui.NewSharedKeyAction("Help", b.helpCmd, false),
	})
}

// Start initializes browser updates.
func (b *Browser) Start() {
	b.Stop()
	//b.GetModel().AddListener(b)
	b.Table.Start()
	//b.CmdBuff().AddListener(b)
	if err := b.Table.GetModel().Refresh(b.prepareContext()); err != nil {
		gologger.Error().Msgf("Browser Start err %v", err)
	}
	b.Refresh()
	// if err := b.GetModel().Watch(b.context); err != nil {
	// 	b.App().Flash().Err(fmt.Errorf("Watcher failed for %s -- %w", b.Resource(), err))
	// }
}

// Stop terminates browser updates.
func (b *Browser) Stop() {
	b.mx.Lock()
	{
		if b.cancelFn != nil {
			b.cancelFn()
			b.cancelFn = nil
		}
	}
	b.mx.Unlock()
	//b.GetModel().RemoveListener(b)
	b.Table.Stop()
}

func (b *Browser) prepareContext() context.Context {
	ctx := context.Background()
	ctx, b.cancelFn = context.WithCancel(ctx)
	if b.contextFn != nil {
		ctx = b.contextFn(ctx)
	}
	return ctx
}

// Name returns the component name.
func (b *Browser) Name() string { return b.Table.Resource() }

// SetContextFn populates a custom context.
func (b *Browser) SetContextFn(f ContextFunc) { b.contextFn = f }

// GetTable returns the underlying table.
func (b *Browser) GetTable() *Table { return b.Table }

func (b *Browser) helpCmd(evt *tcell.EventKey) *tcell.EventKey {

	return evt
}

func (b *Browser) resetCmd(evt *tcell.EventKey) *tcell.EventKey {
	b.Refresh()
	return evt
}
