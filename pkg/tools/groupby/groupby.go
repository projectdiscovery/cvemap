package groupby

import (
	"context"
	"strconv"
	"strings"

	"github.com/projectdiscovery/cvemap"
)

// Params defines the inputs for a group-by operation. It currently supports
// only term facets and facet size. Internally these values are transpiled to
// a cvemap.SearchParams instance with Fields set to ["doc_id"] and Limit = 1
// so that the API returns only the faceted aggregation buckets while keeping
// the response payload small.
//
// Example:
//
//	h := groupby.NewHandler(client)
//	resp, err := h.GroupBy(groupby.Params{
//	    TermFacets: []string{"severity=5", "tags=10"},
//	})
//
// The zero value of Params is invalid – callers must provide at least one
// term facet.
type Params struct {
	// Fields represents the list of facet expressions the caller wishes to
	// compute. Each expression can optionally set a custom size using the
	// "field=size" syntax (e.g. "severity=5").
	Fields []string

	// Query is an optional Lucene-style query that filters the documents
	// before the facet aggregation is executed.
	Query *string

	// FacetSize sets the default number of buckets to return for any facet
	// expression that does not explicitly override its size via the
	// "field=size" form. If nil the server default is used.
	FacetSize *int
}

// Handler provides high-level helpers for performing "group-by" operations via
// facets. All heavy-lifting is delegated to cvemap.Client.SearchVulnerabilities
// so that business logic remains decoupled from CLI concerns.
//
// The zero value of Handler is not valid; always use NewHandler.
// This mirrors the design of pkg/tools/search.Handler for consistency.
type Handler struct {
	client *cvemap.Client
}

// NewHandler returns a new Handler instance that uses the provided cvemap.Client
// for all network operations.
func NewHandler(client *cvemap.Client) *Handler {
	return &Handler{client: client}
}

// GroupBy performs a facet-based aggregation over vulnerabilities. Callers must
// provide at least one term facet via Params.TermFacets. The function sets
// Fields to ["doc_id"] and Limit to 1 to minimise response size as we are only
// interested in the aggregation buckets.
func (h *Handler) GroupBy(params Params) (cvemap.SearchResponse, error) {
	// Enforce maximum facet size of 200 across all inputs to avoid abuse.

	// 1. Clamp FacetSize if provided.
	if params.FacetSize != nil && *params.FacetSize > 200 {
		capped := 200
		params.FacetSize = &capped
	}

	// 2. Inspect each field expression for explicit size overrides (field=size).
	//    If present and size > 200, cap it.
	cappedFields := make([]string, len(params.Fields))
	for i, f := range params.Fields {
		if strings.Contains(f, "=") {
			parts := strings.SplitN(f, "=", 2)
			if len(parts) == 2 {
				if sz, err := strconv.Atoi(parts[1]); err == nil {
					if sz > 200 {
						sz = 200
					}
					f = parts[0] + "=" + strconv.Itoa(sz)
				}
			}
		}
		cappedFields[i] = f
	}

	sp := cvemap.SearchParams{
		TermFacets: cappedFields,
		Fields:     []string{"doc_id"},
		Limit:      cvemap.Ptr(1),
	}
	if params.Query != nil {
		sp.Query = params.Query
	}
	if params.FacetSize != nil {
		sp.FacetSize = params.FacetSize
	}

	return h.client.SearchVulnerabilities(context.Background(), sp)
}
