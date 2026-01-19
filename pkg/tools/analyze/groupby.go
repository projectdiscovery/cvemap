package analyze

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/vulnx"
)

// Handler wraps the vulnx.Client for faceted vulnerability analysis operations.
type Handler struct {
	client *vulnx.Client
}

// NewHandler constructs a new Handler instance.
func NewHandler(client *vulnx.Client) *Handler {
	return &Handler{client: client}
}

// Example Usage:
//	h := analyze.NewHandler(client)
//	resp, err := h.Analyze(analyze.Params{
//		Fields: []string{"severity", "is_kev"},
//	})
//
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Found %d total vulnerabilities\n", resp.Total)

// Params groups the parameters for faceted vulnerability analysis
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

// Analyze performs a facet-based aggregation over vulnerabilities. Callers must
// provide at least one term facet via Params.Fields. The function sets
// Fields to ["doc_id"] and Limit to 1 to minimise response size as we are only
// interested in the aggregation buckets.
func (h *Handler) Analyze(params Params) (vulnx.SearchResponse, error) {
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

	sp := vulnx.SearchParams{
		TermFacets: cappedFields,
		Fields:     []string{"doc_id"},
		Limit:      vulnx.Ptr(1),
	}
	if params.Query != nil {
		sp.Query = params.Query
	}
	if params.FacetSize != nil {
		sp.FacetSize = params.FacetSize
	}

	return h.client.SearchVulnerabilities(context.Background(), sp)
}

// MCPToolSpec returns the MCP tool specification for vulnerability analysis
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnx_analyze",
		mcp.WithDescription("Aggregate vulnerabilities (ANALYZE/facets) over selected fields. NOTE: Use this tool ONLY when instructed by `agent_vulnx` or when the user explicitly asks for an analysis; do NOT call it otherwise."),
		mcp.WithArray("fields",
			mcp.Description("Facet/analyze expressions. Example: ['severity=5', 'vendor=10']. Each entry is either just the field name or 'field=size' to override bucket count (max 200)."),
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
func (h *Handler) MCPHandler(client *vulnx.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
		resp, err := h.Analyze(params)
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: failed to marshal analysis result: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnx) analysis result:\n" + string(b)), nil
	}
}
