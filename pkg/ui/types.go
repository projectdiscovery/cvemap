package ui

import (
	"context"
	"time"

	"github.com/projectdiscovery/cvemap/pkg/dao"
	"github.com/projectdiscovery/cvemap/pkg/model"
	"github.com/projectdiscovery/cvemap/pkg/render"
	"github.com/sahilm/fuzzy"
)

type (
	DropdownSelectedFn func(text string, index int)

	// SortFn represent a function that can sort columnar data.
	SortFn func(rows render.Rows, sortCol SortColumn)

	// SortColumn represents a sortable column.
	SortColumn struct {
		name string
		asc  bool
	}
)

// Lister represents a viewable resource.
type Lister interface {
	// Get returns a resource instance.
	Get(ctx context.Context, path string) (dao.Object, error)
}

// Tabular represents a tabular model.
type Tabular interface {
	Lister

	// Empty returns true if model has no data.
	Empty() bool

	// Count returns the model data count.
	Count() int

	// Peek returns current model data.
	Peek() *render.TableData

	//Watch watches a given resource for changes.
	Watch(context.Context) error

	// Refresh forces a new refresh.
	Refresh(context.Context) error

	// SetRefreshRate sets the model watch loop rate.
	SetRefreshRate(time.Duration)

	// AddListener registers a model listener.
	AddListener(model.TableListener)

	// RemoveListener unregister a model listener.
	RemoveListener(model.TableListener)
}

type Viewer interface {
	Lister
}

type ResourceViewerListener interface {
	ResourceChanged(lines []string, matches fuzzy.Matches)
	ResourceFailed(error)
}
