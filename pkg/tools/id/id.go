package id

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/cvemap"
)

type Handler struct {
	client *cvemap.Client
}

// NewHandler returns a new Handler instance
func NewHandler(client *cvemap.Client) *Handler {
	return &Handler{
		client: client,
	}
}

// Get fetches a single vulnerability document by its ID.
func (h *Handler) Get(id string) (*cvemap.Vulnerability, error) {
	resp, err := h.client.GetVulnerabilityByID(context.Background(), id, nil)
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

// MCPToolSpec returns the MCP tool spec for registration.
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("vulnsh_get_by_id",
		mcp.WithDescription(`Retrieve the COMPLETE vulnerability record for a given identifier from the ProjectDiscovery vulnerability.sh (vulnsh) API.

• Accepts both CVE identifiers (e.g. "CVE-2023-4863") and Nuclei Template IDs (short unique identifiers such as "php-xdebug-rce", NOT full repository paths).
• For CVEs: the returned JSON includes metadata, CVSS metrics, references, exploit information, tags, vendor/product fields, etc.
• For Nuclei templates: the response contains the rendered template metadata plus the original YAML template body so users can copy-paste it directly into a scanner. This is ideal when the prompt asks to "download", "show", or "inspect" a particular template.

Use this tool whenever a prompt asks for full details about a specific vulnerability or template. If the user is unsure of the exact ID, first invoke 'vulnsh_search' to find candidates, then feed the chosen ID here.

Typical triggers:
 • "Tell me everything about CVE-2024-1234"
 • "Show the nuclei template for php-xdebug-rce"
 • "Download the YAML for CVE-2021-44228 exploitation template".`),
		mcp.WithString("id",
			mcp.Required(),
			mcp.Description("The CVE ID or Nuclei Template ID to retrieve (e.g. 'CVE-2024-1234' or 'php-xdebug-rce')."),
		),
	)
}

// MCPHandler returns the MCP handler for this tool.
func (h *Handler) MCPHandler(client *cvemap.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := request.RequireString("id")
		if err != nil || id == "" {
			return mcp.NewToolResultError("ProjectDiscovery vulnsh: 'id' is required and must be a string."), nil
		}
		vuln, err := h.Get(id)
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnsh: " + err.Error()), nil
		}
		b, err := json.MarshalIndent(vuln, "", "  ")
		if err != nil {
			return mcp.NewToolResultError("ProjectDiscovery vulnsh: failed to marshal vulnerability: " + err.Error()), nil
		}
		return mcp.NewToolResultText("ProjectDiscovery vulnerability.sh (vulnsh) result for ID '" + id + "':\n" + string(b)), nil
	}
}
