package groupby

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
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

	// Query is an optional Bleve query expression that filters the documents
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
		cappedFields[i] = strings.ReplaceAll(f, "=", ":")
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

// MCPToolSpec returns the MCP tool spec for registration.
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnx_groupby",
		mcp.WithDescription("Aggregate vulnerabilities (GROUP BY/facets) over selected fields. NOTE: Use this tool ONLY when instructed by `agent_vulnx` or when the user explicitly asks for a group-by; do NOT call it otherwise."),
		mcp.WithArray("fields",
			mcp.Description("Facet/group-by expressions. Example: ['severity=5', 'vendor=10']. Each entry is either just the field name or 'field=size' to override bucket count (max 200)."),
			mcp.Items(map[string]any{"type": "string"}),
			mcp.Required(),
		),
		mcp.WithString("query",
			mcp.Description("Optional Bleve-inspired query filter (use '&&', '||' for logical operations) applied before aggregation. Combine field names and operators to narrow the data set (see 'vulnx_fields_list' for valid fields)."),
		),
		mcp.WithNumber("facet_size",
			mcp.Description("Default bucket count when 'field=size' is not provided. Max 200."),
		),
	)
}

// MCPHandler returns the MCP handler for this tool.
func (h *Handler) MCPHandler(client *cvemap.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fields, err := request.RequireStringSlice("fields")
		if err != nil || len(fields) == 0 {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: 'fields' is required and must be a string array."), nil
		}
		// fix request fields format
		for i, f := range fields {
			if strings.Contains(f, "=") {
				fields[i] = strings.ReplaceAll(f, "=", ":")
			}
		}
		query := request.GetString("query", "")
		var queryPtr *string
		if query != "" {
			queryPtr = &query
		}
		facetSize := request.GetInt("facet_size", 0)
		var facetSizePtr *int
		if facetSize > 0 {
			facetSizePtr = &facetSize
		}
		params := Params{
			Fields:    fields,
			Query:     queryPtr,
			FacetSize: facetSizePtr,
		}
		resp, err := h.GroupBy(params)
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: failed to marshal groupby result: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnx) groupby result:\n" + string(b)), nil
	}
}
