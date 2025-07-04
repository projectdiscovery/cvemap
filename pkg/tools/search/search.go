package search

import (
	"context"

	"github.com/projectdiscovery/cvemap"
)

// Handler provides high-level helpers around the vulnerability search
// endpoint. It mirrors the design of pkg/tools/id.Handler for
// consistency across tools.
//
// All methods are thin wrappers over the corresponding cvemap.Client
// helpers so that business logic remains decoupled from CLI concerns.
// The type is intentionally small to keep instantiation and use
// lightweight.
//
// Example:
//
//	h := search.NewHandler(client)
//	resp, err := h.Search(cvemap.SearchParams{Query: cvemap.Ptr("severity:critical")})
//
// The zero value of Handler is not valid; always use NewHandler.
type Handler struct {
	client *cvemap.Client
}

// NewHandler returns a new Handler instance that uses the provided
// cvemap.Client for all network operations.
func NewHandler(client *cvemap.Client) *Handler {
	return &Handler{client: client}
}

// Search performs a full-text search across vulnerabilities using the
// supplied parameters. It delegates the heavy-lifting to
// cvemap.Client.SearchVulnerabilities and simply forwards the request
// context.
func (h *Handler) Search(params cvemap.SearchParams) (cvemap.SearchResponse, error) {
	return h.client.SearchVulnerabilities(context.Background(), params)
}
