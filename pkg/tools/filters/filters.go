package filters

import (
	"context"

	"github.com/projectdiscovery/cvemap"
)

// Handler provides a thin wrapper around cvemap.Client.GetVulnerabilityFilters so
// that CLI tooling can remain decoupled from the API client. The design mirrors
// pkg/tools/id.Handler and pkg/tools/search.Handler for consistency.
//
// The zero value of Handler is not valid; always instantiate the type via
// NewHandler.
type Handler struct {
	client *cvemap.Client
}

// NewHandler returns a new Handler that will use the supplied *cvemap.Client
// for all network operations. The provided client must be fully configured and
// ready for use.
func NewHandler(client *cvemap.Client) *Handler {
	return &Handler{client: client}
}

// List retrieves the full list of vulnerability filter definitions from the
// CVEMap API. It forwards the call to cvemap.Client.GetVulnerabilityFilters
// using a background context.
func (h *Handler) List() ([]cvemap.VulnerabilityFilter, error) {
	return h.client.GetVulnerabilityFilters(context.Background())
}
