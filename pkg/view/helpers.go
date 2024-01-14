package view

import (
	"context"

	"github.com/projectdiscovery/cvemap/pkg/constant"
	"github.com/projectdiscovery/cvemap/pkg/model"
	"github.com/projectdiscovery/cvemap/pkg/ui"
	errorutil "github.com/projectdiscovery/utils/errors"
)

func extractApp(ctx context.Context) (*App, error) {
	app, ok := ctx.Value(constant.KeyApp).(*App)
	if !ok {
		return nil, errorutil.New("No application found in context")
	}

	return app, nil
}

func describeResource(app *App, m ui.Tabular, resource, path string) {
	v := NewLiveView(app, "Describe", model.NewDescribe(resource, path))
	if err := app.inject(v); err != nil {
		app.Flash().Err(err)
	}
}
