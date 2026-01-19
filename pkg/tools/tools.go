package tools

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/vulnx"
	"github.com/projectdiscovery/vulnx/pkg/tools/agentvulnx"
	"github.com/projectdiscovery/vulnx/pkg/tools/analyze"
	"github.com/projectdiscovery/vulnx/pkg/tools/filters"
	"github.com/projectdiscovery/vulnx/pkg/tools/id"
	"github.com/projectdiscovery/vulnx/pkg/tools/search"
)

// MCPTool is the interface all tools must implement for MCP support.
type MCPTool interface {
	// MCPToolSpec returns the MCP tool spec for registration.
	MCPToolSpec() mcp.Tool
	// MCPHandler returns the MCP handler for this tool.
	MCPHandler(client *vulnx.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
}

// AllMCPTools returns all MCPTool implementations for ProjectDiscovery vulnerability.sh (vulnx) MCP integration.
func AllMCPTools(client *vulnx.Client) []MCPTool {
	return []MCPTool{
		filters.NewHandler(client),
		search.NewHandler(client),
		id.NewHandler(client),
		analyze.NewHandler(client),
		agentvulnx.NewHandler(client),
	}
}

// // AllMCPPrompts returns all prompt templates for ProjectDiscovery vulnerability.sh (vulnx) MCP integration.
// func AllMCPPrompts(client *vulnx.Client) []templates.PromptTemplate {
// 	return templates.AllPromptTemplates(client)
// }
