package view

import (
	"context"

	"github.com/projectdiscovery/cvemap/pkg/model"
	"github.com/projectdiscovery/cvemap/pkg/ui"
)

type (
	// EnterFunc represents an enter key action.
	EnterFunc func(app *App, model ui.Tabular, resource, path string)

	// ContextFunc enhances a given context.
	ContextFunc func(context.Context) context.Context

	// BindKeysFunc adds new menu actions.
	BindKeysFunc func(ui.KeyActions)
)

// Viewer represents a component viewer.
type Viewer interface {
	model.Component

	// Actions returns active menu bindings.
	Actions() ui.KeyActions

	// App returns an app handle.
	App() *App

	// Refresh updates the viewer
	Refresh()
}

// TableViewer represents a tabular viewer.
type TableViewer interface {
	Viewer

	// Table returns a table component.
	GetTable() *Table
}

// ResourceViewer represents a generic resource viewer.
type ResourceViewer interface {
	TableViewer

	Resource() string

	// SetContextFn provision a custom context.
	SetContextFn(ContextFunc)

	// AddBindKeys provision additional key bindings.
	AddBindKeysFn(BindKeysFunc)
}

// ViewerFunc returns a viewer matching a given gvr.
type ViewerFunc func(string) ResourceViewer

// MetaViewer represents a registered meta viewer.
type MetaViewer struct {
	viewerFn ViewerFunc
	enterFn  EnterFunc
}

// MetaViewers represents a collection of meta viewers.
type MetaViewers map[string]MetaViewer
