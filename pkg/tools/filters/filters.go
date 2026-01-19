package filters

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/vulnx"
)

// Handler provides a thin wrapper around vulnx.Client.GetVulnerabilityFilters so
// that CLI tooling can remain decoupled from the API client. The design mirrors
// pkg/tools/id.Handler and pkg/tools/search.Handler for consistency.
//
// The zero value of Handler is not valid; always instantiate the type via
// NewHandler.
type Handler struct {
	client *vulnx.Client
}

// NewHandler returns a new Handler that will use the supplied *vulnx.Client
// for all network operations. The provided client must be fully configured and
// ready for use.
func NewHandler(client *vulnx.Client) *Handler {
	return &Handler{client: client}
}

// List retrieves the full list of vulnerability filter definitions from the
// CVEMap API. It forwards the call to vulnx.Client.GetVulnerabilityFilters
// using a background context.
func (h *Handler) List() ([]vulnx.VulnerabilityFilter, error) {
	return h.client.GetVulnerabilityFilters(context.Background())
}

// MCPToolSpec returns the MCP tool spec for registration.
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnx_fields_list",
		mcp.WithDescription("List all available fields in the ProjectDiscovery vulnerability.sh API. NOTE: Call this tool ONLY when the `agent_vulnx` tool explicitly instructs you to do so, or when the user directly requests it; otherwise do not invoke it."),
	)
}

// MCPHandler returns the MCP handler for this tool.
func (h *Handler) MCPHandler(client *vulnx.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		filters, err := h.List()
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(filters, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnx: failed to marshal fields: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnx) fields:\n" + string(b)), nil
	}
}
