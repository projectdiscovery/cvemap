package search

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
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

// MCPToolSpec returns the MCP tool spec for registration.
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnsh_search",
		mcp.WithDescription("Search vulnerabilities with Bleve-inspired query syntax (use '&&' and '||' instead of 'AND', 'OR'). NOTE: Use this tool ONLY when `agent_vulnx` explicitly instructs you or when the user directly asks for a search; otherwise do not invoke it."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("Bleve-inspired query expression (e.g. 'severity:critical && product:atlassian'). Combine any fields from 'vulnsh_fields_list'."),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum results per call (default 5, cap 100)."),
		),
		mcp.WithNumber("offset",
			mcp.Description("Starting index for pagination (default 0)."),
		),
		mcp.WithArray("fields",
			mcp.Description("Optional list of fields to include in the response. Omit for defaults, [] for full payload."),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("sort_asc",
			mcp.Description("Field name to sort ascending."),
		),
		mcp.WithString("sort_desc",
			mcp.Description("Field name to sort descending."),
		),
	)
}

// MCPHandler returns the MCP handler for this tool.
func (h *Handler) MCPHandler(client *cvemap.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query, err := request.RequireString("query")
		if err != nil || query == "" {
			return mcp.NewToolResultError("ProjectDiscovery vulnsh: 'query' is required and must be a string."), nil
		}
		limit := request.GetInt("limit", 5)
		if limit > 100 {
			limit = 100
		}
		offset := request.GetInt("offset", 0)

		// Prepare base search parameters
		params := cvemap.SearchParams{
			Query:  &query,
			Limit:  &limit,
			Offset: &offset,
		}

		// Handle optional 'fields' array
		fields := request.GetStringSlice("fields", nil)
		defaultFields := []string{"cve_id", "name", "remediation", "cve_created_at", "poc_count", "doc_type", "updated_at", "impact", "description", "severity", "cvss_score", "epss_score", "is_kev", "is_vkev", "is_oss", "is_patch_available", "is_poc", "is_remote"}
		switch {
		case fields == nil:
			// No parameter provided – apply defaults to reduce payload size
			params.Fields = defaultFields
		case len(fields) == 0:
			// Explicit empty array means no field filtering (full document)
		default:
			params.Fields = fields
		}

		// Sorting parameters (optional)
		sortAsc := request.GetString("sort_asc", "")
		if sortAsc != "" {
			params.SortAsc = &sortAsc
		}
		sortDesc := request.GetString("sort_desc", "")
		if sortDesc != "" {
			params.SortDesc = &sortDesc
		}

		resp, err := h.Search(params)
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnsh: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnsh: failed to marshal search result: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnsh) search result:\n" + string(b)), nil
	}
}
