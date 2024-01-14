package model

import (
	"context"
	"time"

	"github.com/derailed/tview"
	"github.com/projectdiscovery/cvemap/pkg/dao"
	"github.com/projectdiscovery/cvemap/pkg/render"
	"github.com/sahilm/fuzzy"
)

const (
	maxReaderRetryInterval   = 2 * time.Minute
	defaultReaderRefreshRate = 5 * time.Second
)

// Igniter represents a runnable view.
type Igniter interface {
	// Start starts a component.
	Init(ctx context.Context) error

	// Start starts a component.
	Start()

	// Stop terminates a component.
	Stop()
}

// Hinter represent a menu mnemonic provider.
type Hinter interface {
	// Hints returns a collection of menu hints.
	Hints() MenuHints
}

// Primitive represents a UI primitive.
type Primitive interface {
	tview.Primitive

	// Name returns the view name.
	Name() string
}

// Component represents a ui component.
type Component interface {
	Primitive
	Igniter
	Hinter
}

// Renderer represents a resource renderer.
type Renderer interface {
	// Render converts raw resources to tabular data.
	Render(o interface{}, ns string, row *render.Row) error

	// Header returns the resource header.
	Header() render.Header
}

// ResourceMeta represents model info about a resource.
type ResourceMeta struct {
	DAO      dao.Accessor
	Renderer Renderer
}

type ResourceViewerListener interface {
	ResourceChanged(lines []string, matches fuzzy.Matches)
	ResourceFailed(error)
}

type ViewerToggleOpts map[string]bool

type ResourceViewer interface {
	GetPath() string
	Filter(string)
	ClearFilter()
	Peek() []string
	SetOptions(context.Context, ViewerToggleOpts)
	Watch(context.Context) error
	Refresh(context.Context) error
	AddListener(ResourceViewerListener)
	RemoveListener(ResourceViewerListener)
}
