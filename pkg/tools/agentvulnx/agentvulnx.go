package agentvulnx

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/cvemap"
)

// Handler implements the MCPTool interface for the agent_vulnx planner.
//
// The tool converts a natural-language vulnerability task into a structured
// execution plan (Markdown) that guides an LLM or user through the optimal
// sequence of ProjectDiscovery vulnerability.sh MCP tools. It is analogous to
// the generic "sequential thinking" tool but specialised for vulnerability,
// CVE, and Nuclei-template analysis workflows.
//
// Typical usage:
//   1. The user (or another tool) calls agent_vulnx with a free-form task such
//      as "Find recent critical RCEs in WordPress".
//   2. agent_vulnx returns a prompt skeleton containing:
//        • Proposed tool chain (vulnsh_fields_list → vulnsh_search → …)
//        • Step-by-step rationale for each action
//        • Space for clarification questions and an ethical notice
//   3. Down-stream automation or an analyst fills in the details and executes
//      the referenced MCP tools.
//
// NOTE: This tool is the **only** component authorised to instruct calls to
// vulnsh_fields_list, vulnsh_search, vulnsh_groupby, and vulnsh_get_by_id unless
// the user explicitly demands those tools.
//
// Input Parameters (JSON Schema):
//   task: string (required) – Plain-language description of the vulnerability
//         question or objective.
//
// Output: A Markdown document embodying the planning framework described above.
// It purposefully mirrors the sequentialthinking guidance so downstream agents
// can iterate, revise, and branch their reasoning when needed.

type Handler struct {
	client *cvemap.Client
}

// NewHandler returns a new planner handler instance.
func NewHandler(client *cvemap.Client) *Handler {
	return &Handler{client: client}
}

// MCPToolSpec returns the MCP specification for agent_vulnx.
func (h *Handler) MCPToolSpec() mcp.Tool {
	return mcp.NewTool("agent_vulnx",
		mcp.WithDescription(`Convert a natural-language vulnerability task into a structured execution plan. The plan follows a "sequential thinking" style tailored to ProjectDiscovery vulnerability.sh MCP tools.

When to use this tool:
- Any time a user poses an open-ended vulnerability, CVE, exploit, or template-related request.
- When another tool or the system needs an explicit, step-by-step plan before invoking vulnsh_* tools.

Key features:
- Breaks the problem into ordered tool calls (fields_list → search → groupby → get_by_id).
- Provides rationale for each step and optional clarification questions.
- Encourages iterative refinement, branching, and hypothesis verification like sequentialthinking.
- Emits a Markdown skeleton that downstream agents can fill out.

Parameters:
- task (string, required): Plain-language description of the vulnerability task.`),
		mcp.WithString("task",
			mcp.Required(),
			mcp.Description("Plain-language vulnerability or CVE-related task description (e.g. 'Analyze CVE-2024-1234')"),
		),
	)
}

var prompt = `
Execute a vulnerability analysis using the LOOP framework, systematically progressing through each stage and utilizing the specified tools at the appropriate steps. Document each iteration and ensure queries are refined for optimal results.

Start with Field Discovery to identify all available fields and examples. Use insights from this stage to design effective Bleve-inspired queries. If queries fail, revisit and iterate with improvements. Use optional tools for deeper insights and summarize the findings upon completion.

# Steps

1. **Field Discovery**: 
   - Use *vulnsh_fields_list* to enumerate available fields and example values.
   
2. **Query Design**:
   - Draft Bleve-inspired queries based on the insights from Field Discovery.

3. **vulnsh_search Execution**:
   - Run the designed queries and analyze the results. Aim to refine queries if errors or irrelevant results occur.

4. **Result Assessment**:
   - Assess result counts and their relevance. Make necessary iterative adjustments to queries, focusing on precision and discovering meaningful insights.

5. **Aggregation or Detail**:
   - For statistical analysis or trend visualization, use *vulnsh_groupby*. For deeper insights into specific vulnerabilities, use *vulnsh_get_by_id*.

6. **Completion**:
   - Summarize the analysis, capturing key findings, associated risks, remediation proposals, and suggested next steps.

# Output Format

The output should summarize key findings in a clear and structured format, capturing:
- Relevant fields discovered
- Effective query parameters used
- Notable results and observations
- Recommended next steps based on the analysis

# Examples

- **Field Discovery & Query Design**:
   - "Using *vulnsh_fields_list*, identified fields: severity, cvss_score, tags. Constructed initial query: 'severity:critical && tags:rce'."
  
- **vulnsh_search Execution & Result Analysis**:
   - "Executed query and observed 50 relevant results indicating high-risk vulnerabilities. Refined query by adjusting filters to: 'severity:critical && cvss_score:>7'."

- **Completion Summary**:
   - "Summarized findings: Detected 10 critical vulnerabilities in 30 days window. Suggested remediation: Patch updates and increased monitoring of domains."

# Notes

- Ensure valid field names in queries, use valid operators (&&, ||).
- If queries return errors or zero results, revisit Field Discovery or modify conditions to improve relevance.
- Explore advanced options like 'description:<keyword>' as a contingency for detailed search needs.
- Loosen filters when necessary and consider synonyms or alternate keywords for broader results.
- Document each step in the iteration log systematically for tracking and evaluations.

**Task:**
`

// MCPHandler generates the execution-plan prompt based on the provided task.
func (h *Handler) MCPHandler(client *cvemap.Client) func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		task, err := request.RequireString("task")
		if err != nil || task == "" {
			return mcp.NewToolResultError("agent_vulnx: 'task' is required and must be a non-empty string"), nil
		}

		plan := prompt + "\n" + task

		return mcp.NewToolResultText(plan), nil
	}
}
