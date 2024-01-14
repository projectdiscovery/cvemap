package model

import (
	"context"
	"fmt"

	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/projectdiscovery/cvemap/pkg/dao"
	"github.com/projectdiscovery/cvemap/pkg/render"
	"github.com/projectdiscovery/gologger"
)

const initRefreshRate = 300 * time.Millisecond

// TableListener represents a table model listener.
type TableListener interface {
	// TableDataChanged notifies the model data changed.
	TableDataChanged(*render.TableData)
}

// Table represents a table model.
type Table struct {
	resource    string
	data        *render.TableData
	listeners   []TableListener
	mx          sync.RWMutex
	refreshRate time.Duration
}

// NewTable returns a new table model.
func NewTable(res string) *Table {
	return &Table{
		resource:    res,
		data:        render.NewTableData(),
		refreshRate: 2 * time.Second,
	}
}

// AddListener adds a new model listener.
func (t *Table) AddListener(l TableListener) {
	t.listeners = append(t.listeners, l)
}

// RemoveListener delete a listener from the list.
func (t *Table) RemoveListener(l TableListener) {
	victim := -1
	for i, lis := range t.listeners {
		if lis == l {
			victim = i
			break
		}
	}

	if victim >= 0 {
		t.mx.Lock()
		defer t.mx.Unlock()
		t.listeners = append(t.listeners[:victim], t.listeners[victim+1:]...)
	}
}

// Empty returns true if no model data.
func (t *Table) Empty() bool {
	return t.data.Empty()
}

// Count returns the row count.
func (t *Table) Count() int {
	return t.data.Count()
}

// Peek returns model data.
func (t *Table) Peek() *render.TableData {
	t.mx.RLock()
	defer t.mx.RUnlock()

	return t.data.Clone()
}

// SetRefreshRate sets model refresh duration.
func (t *Table) SetRefreshRate(d time.Duration) {
	t.refreshRate = d
}

// Watch initiates model updates.
func (t *Table) Watch(ctx context.Context) error {
	if err := t.refresh(ctx); err != nil {
		return err
	}
	//go t.updater(ctx)

	return nil
}

// Refresh updates the table content.
func (t *Table) Refresh(ctx context.Context) error {
	return t.refresh(ctx)
}

// Get returns a resource instance if found, else an error.
func (t *Table) Get(ctx context.Context, path string) (dao.Object, error) {
	meta, err := getMeta(ctx, t.resource)
	if err != nil {
		return nil, err
	}

	return meta.DAO.Get(ctx, path)
}

func (t *Table) updater(ctx context.Context) {
	defer gologger.Debug().Msgf("TABLE-UPDATER canceled -- %q", t.resource)

	bf := backoff.NewExponentialBackOff()
	bf.InitialInterval, bf.MaxElapsedTime = initRefreshRate, maxReaderRetryInterval
	rate := initRefreshRate
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(rate):
			rate = t.refreshRate
			err := backoff.Retry(func() error {
				return t.refresh(ctx)
			}, backoff.WithContext(bf, ctx))
			if err != nil {
				gologger.Error().Msgf("Retry failed")
				t.fireTableLoadFailed(err)
				return
			}
		}
	}
}

func (t *Table) refresh(ctx context.Context) error {
	if err := t.reconcile(ctx); err != nil {
		return err
	}
	t.fireTableChanged(t.Peek())

	return nil
}

func (t *Table) reconcile(ctx context.Context) error {
	t.mx.Lock()
	defer t.mx.Unlock()
	meta := resourceMeta(t.resource)

	var (
		oo  []dao.Object
		err error
	)
	oo, err = t.list(ctx, meta.DAO)

	if err != nil {
		return err
	}

	var rows render.Rows
	if len(oo) > 0 {
		rows = make(render.Rows, len(oo))
		if err := hydrate("", oo, rows, meta.Renderer); err != nil {
			return err
		}

	}

	t.data.Clear()
	t.data.Update(rows)
	t.data.SetHeader(meta.Renderer.Header())

	if len(t.data.Header) == 0 {
		return fmt.Errorf("fail to list resource %s", t.resource)
	}

	return nil
}

func (t *Table) fireTableChanged(data *render.TableData) {
	t.mx.RLock()
	defer t.mx.RUnlock()

	for _, l := range t.listeners {
		l.TableDataChanged(data)
	}
}

func (t *Table) list(ctx context.Context, a dao.Accessor) ([]dao.Object, error) {

	return a.List(ctx)
}

func getMeta(ctx context.Context, res string) (ResourceMeta, error) {
	meta := resourceMeta(res)
	return meta, nil
}

func resourceMeta(res string) ResourceMeta {
	meta, ok := Registry[res]
	if !ok {
		gologger.Debug().Msg(fmt.Sprintf("No registry found for %v", res))
	}
	return meta
}

func (t *Table) fireTableLoadFailed(err error) {
	// for _, l := range t.listeners {
	// 	l.TableLoadFailed(err)
	// }
}

// ----------------------------------------------------------------------------
// Helpers...

func hydrate(ns string, oo []dao.Object, rr render.Rows, re Renderer) error {
	for i, o := range oo {
		if err := re.Render(o, ns, &rr[i]); err != nil {
			return err
		}
	}

	return nil
}
