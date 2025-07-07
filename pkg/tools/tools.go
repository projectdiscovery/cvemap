package tools

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/cvemap"
	"github.com/projectdiscovery/cvemap/pkg/tools/agentvulnx"
	"github.com/projectdiscovery/cvemap/pkg/tools/filters"
	"github.com/projectdiscovery/cvemap/pkg/tools/groupby"
	"github.com/projectdiscovery/cvemap/pkg/tools/id"
	"github.com/projectdiscovery/cvemap/pkg/tools/search"
)

// MCPTool is the interface all tools must implement for MCP support.
type MCPTool interface {
	// MCPToolSpec returns the MCP tool spec for registration.
	MCPToolSpec() mcp.Tool
	// MCPHandler returns the MCP handler for this tool.
	MCPHandler(client *cvemap.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)
}

// AllMCPTools returns all MCPTool implementations for ProjectDiscovery vulnerability.sh (vulnx) MCP integration.
func AllMCPTools(client *cvemap.Client) []MCPTool {
	return []MCPTool{
		filters.NewHandler(client),
		groupby.NewHandler(client),
		id.NewHandler(client),
		search.NewHandler(client),
		agentvulnx.NewHandler(client),
	}
}

// // AllMCPPrompts returns all prompt templates for ProjectDiscovery vulnerability.sh (vulnx) MCP integration.
// func AllMCPPrompts(client *cvemap.Client) []templates.PromptTemplate {
// 	return templates.AllPromptTemplates(client)
// }
