package filters

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
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

// MCPToolSpec returns the MCP tool spec for registration.
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnsh_fields_list",
		mcp.WithDescription(`Comprehensive reference for the ProjectDiscovery vulnerability.sh (vulnsh) API field catalog. Use this tool whenever a user (or an LLM) needs to know which fields/attributes are available, their data types, example values, and whether they are searchable, sortable, or groupable. The response is a JSON array describing every field and includes sample Lucene-style query snippets, making it a one-stop cheat-sheet for constructing filters, sort clauses, pagination parameters, or group-by aggregations. Invoke this tool whenever the prompt mentions field names, available columns, schema, filtering, sorting, grouping, or how to write a query against the vulnerability.sh dataset.`),
	)
}

// MCPHandler returns the MCP handler for this tool.
func (h *Handler) MCPHandler(client *cvemap.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filters, err := h.List()
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnsh: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(filters, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnsh: failed to marshal fields: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnsh) fields:\n" + string(b)), nil
	}
}
