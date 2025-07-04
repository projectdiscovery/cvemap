package templates

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/cvemap"
)

// PromptTemplate defines the interface for vulnerability analysis prompt templates
type PromptTemplate interface {
	// MCPPromptSpec returns the MCP prompt spec for registration
	MCPPromptSpec() mcp.Prompt
	// MCPPromptHandler returns the MCP prompt handler
	MCPPromptHandler(client *cvemap.Client) func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error)
}

// Handler provides prompt template functionality for vulnerability analysis
type Handler struct {
	client *cvemap.Client
}

// NewHandler returns a new prompt template handler
func NewHandler(client *cvemap.Client) *Handler {
	return &Handler{client: client}
}

// AllPromptTemplates returns all available prompt templates
func AllPromptTemplates(client *cvemap.Client) []PromptTemplate {
	handler := NewHandler(client)
	return []PromptTemplate{
		&VulnerabilityAnalysisPrompt{handler: handler},
		&ThreatIntelligencePrompt{handler: handler},
		&SecurityResearchPrompt{handler: handler},
		&GeneralVulnAssistantPrompt{handler: handler},
		&VulnshSearchReviewPrompt{handler: handler},
	}
}

// VulnerabilityAnalysisPrompt helps users analyze vulnerabilities effectively
type VulnerabilityAnalysisPrompt struct {
	handler *Handler
}

func (p *VulnerabilityAnalysisPrompt) MCPPromptSpec() mcp.Prompt {
	return mcp.NewPrompt(
		"vulnerability_analysis_guide",
		mcp.WithPromptDescription("Expert guidance for analyzing vulnerabilities using ProjectDiscovery's vulnerability.sh API. This template helps convert generic vulnerability queries into structured analysis workflows."),
		mcp.WithArgument("query",
			mcp.ArgumentDescription("Your vulnerability analysis question or requirement (e.g., 'find critical RCE vulnerabilities in web applications', 'analyze CVE-2024-1234', 'show me recent WordPress vulnerabilities')"),
			mcp.RequiredArgument(),
		),
		mcp.WithArgument("analysis_type",
			mcp.ArgumentDescription("Type of analysis needed: 'research', 'threat_hunting', 'impact_assessment', 'remediation_planning', or 'general'"),
		),
	)
}

func (p *VulnerabilityAnalysisPrompt) MCPPromptHandler(client *cvemap.Client) func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		args := request.Params.Arguments
		query := getStringArg(args, "query", "")
		analysisType := getStringArg(args, "analysis_type", "general")

		systemPrompt := `# Vulnerability Analysis Expert Assistant

You are an expert vulnerability analyst helping users leverage ProjectDiscovery's vulnerability.sh API through MCP tools. Your role is to:

1. **Understand the user's intent** and convert generic vulnerability queries into structured analysis workflows
2. **Guide efficient tool usage** by suggesting the optimal sequence of MCP tool calls
3. **Provide context and insights** about vulnerabilities, their impact, and remediation strategies

## Available MCP Tools:
- **vulnsh_fields_list**: Lists all available vulnerability fields and their examples
- **vulnsh_search**: Full-text search across vulnerabilities with Bleve query syntax
- **vulnsh_groupby**: Facet-based aggregations for statistical analysis
- **vulnsh_get_by_id**: Fetch detailed information about specific vulnerabilities

## Analysis Workflow Strategy:

### Step 1: Always Start with Field Discovery
- Use **vulnsh_fields_list** first to understand available search fields
- This provides the foundation for constructing precise queries

### Step 2: Plan Your Query Strategy
Based on the user's intent, construct Bleve query syntax using available fields:
- **Severity**: severity:critical, severity:high
- **CVSS Score**: cvss_score:[7.0 TO 10.0]
- **Exploit Status**: is_exploited:true, is_kev:true
- **Technology**: tags:wordpress, tags:nginx, tags:apache
- **Time Range**: published_date:[2024-01-01 TO 2024-12-31]
- **Vulnerability Type**: tags:rce, tags:sqli, tags:xss, tags:lfi

### Step 3: Execute Targeted Analysis
- Use **vulnsh_search** for finding specific vulnerabilities
- Use **vulnsh_groupby** for statistical analysis and trends
- Use **vulnsh_get_by_id** for detailed vulnerability investigation

### Step 4: Provide Actionable Insights
- Explain vulnerability impact and risk levels
- Suggest remediation strategies
- Highlight related vulnerabilities or patterns

## Query Translation Examples:

**Generic Query**: "Show me critical web application vulnerabilities"
**Structured Approach**: 
1. vulnsh_fields_list (understand available fields)
2. vulnsh_search with query: "severity:critical AND (tags:web OR tags:http OR tags:webapp)"
3. vulnsh_groupby with fields: ["tags", "cvss_score"] for pattern analysis

**Generic Query**: "Find recent WordPress vulnerabilities"
**Structured Approach**:
1. vulnsh_fields_list (get field options)
2. vulnsh_search with query: "tags:wordpress AND published_date:[2024-01-01 TO *]"
3. vulnsh_groupby with fields: ["severity", "is_exploited"] for risk assessment

**Generic Query**: "Analyze CVE-2024-1234"
**Structured Approach**:
1. vulnsh_get_by_id with id: "CVE-2024-1234"
2. vulnsh_search with query: "tags:* AND cvss_score:[X TO *]" (where X is the CVE's CVSS score)
3. Provide detailed analysis of impact, exploitation, and remediation

## Output Instructions (MANDATORY)
Follow this exact Markdown template – no extra prose:

### Proposed Tool Chain
1. vulnsh_get_by_id – detailed vulnerability analysis

### Step-by-Step Rationale
- Exploitation complexity assessment
- Attack vector feasibility analysis
- Defensive countermeasure evaluation
- Impact and risk quantification

### Clarification Questions
- question (or "None")

### Ethical Notice
Include only if the request involves exploitation or illegal activity.

## Current User Query Analysis:`

		userPrompt := "User Query: " + query + "\n\n"

		analysisContext := ""
		switch analysisType {
		case "research":
			analysisContext = `Analysis Type: RESEARCH
Focus on: Deep technical analysis, vulnerability chains, attack vectors, and research methodologies.
Provide: Detailed technical insights, related vulnerabilities, and research opportunities.`
		case "threat_hunting":
			analysisContext = `Analysis Type: THREAT HUNTING
Focus on: Active exploitation indicators, threat actor patterns, and IOCs.
Provide: Exploited vulnerabilities, attack patterns, and defensive strategies.`
		case "impact_assessment":
			analysisContext = `Analysis Type: IMPACT ASSESSMENT
Focus on: Risk scoring, business impact, and prioritization.
Provide: CVSS analysis, affected systems, and risk mitigation priorities.`
		case "remediation_planning":
			analysisContext = `Analysis Type: REMEDIATION PLANNING
Focus on: Patch availability, workarounds, and implementation strategies.
Provide: Remediation timelines, patch information, and mitigation techniques.`
		default:
			analysisContext = `Analysis Type: GENERAL
Focus on: Comprehensive vulnerability analysis and recommendations.
Provide: Balanced technical and strategic insights.`
		}

		return &mcp.GetPromptResult{
			Description: fmt.Sprintf("Vulnerability analysis guidance for: %s", query),
			Messages: []mcp.PromptMessage{
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(systemPrompt),
				},
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(userPrompt + analysisContext + "\n\nPlease guide me through the optimal MCP tool sequence to address this query effectively."),
				},
			},
		}, nil
	}
}

// ThreatIntelligencePrompt focuses on threat intelligence and exploitation analysis
type ThreatIntelligencePrompt struct {
	handler *Handler
}

func (p *ThreatIntelligencePrompt) MCPPromptSpec() mcp.Prompt {
	return mcp.NewPrompt(
		"threat_intelligence_guide",
		mcp.WithPromptDescription("Specialized guidance for threat intelligence analysis using vulnerability data. Focuses on exploited vulnerabilities, threat actor TTPs, and active threat campaigns."),
		mcp.WithArgument("threat_focus",
			mcp.ArgumentDescription("Specific threat intelligence focus (e.g., 'APT campaigns', 'ransomware vulnerabilities', 'zero-day tracking', 'KEV analysis')"),
			mcp.RequiredArgument(),
		),
		mcp.WithArgument("time_range",
			mcp.ArgumentDescription("Time range for analysis (e.g., 'last 30 days', '2024', 'last quarter')"),
		),
	)
}

func (p *ThreatIntelligencePrompt) MCPPromptHandler(client *cvemap.Client) func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		args := request.Params.Arguments
		threatFocus := getStringArg(args, "threat_focus", "")
		timeRange := getStringArg(args, "time_range", "last 90 days")

		systemPrompt := `# Threat Intelligence Analysis Expert

You are a specialized threat intelligence analyst focusing on vulnerability exploitation patterns and threat actor behavior. Your expertise includes:

## Core Capabilities:
- **Exploitation Analysis**: Identify actively exploited vulnerabilities and attack patterns
- **KEV Tracking**: Monitor CISA Known Exploited Vulnerabilities catalog
- **Threat Actor Profiling**: Analyze vulnerability preferences and attack chains
- **Campaign Analysis**: Track vulnerability usage in threat campaigns

## Threat Intelligence Workflow:

### Phase 1: Exploitation Landscape Assessment
Tool Sequence:
1. vulnsh_fields_list (identify exploitation-related fields)
2. vulnsh_search with query: "is_exploited:true AND is_kev:true"
3. vulnsh_groupby with fields: ["tags", "severity", "cvss_score"]

### Phase 2: Temporal Analysis
Tool Sequence:
1. vulnsh_search with time-bounded queries
2. vulnsh_groupby with fields: ["published_date", "is_exploited"]
3. Trend analysis and pattern identification

### Phase 3: Technology Impact Assessment
Tool Sequence:
1. vulnsh_groupby with fields: ["tags", "is_exploited"] 
2. vulnsh_search for high-risk technology stacks
3. Cross-reference with public exploit databases

## Key Query Patterns for Threat Intelligence:

**Active Exploitation Tracking**:
- "is_exploited:true AND published_date:[2024-01-01 TO *]"
- "is_kev:true AND cvss_score:[7.0 TO 10.0]"

**Zero-Day Monitoring**:
- "tags:zero-day OR tags:0day"
- "cvss_score:[9.0 TO 10.0] AND is_exploited:true"

**Ransomware-Related Vulnerabilities**:
- "tags:ransomware OR tags:rce OR tags:privilege-escalation"
- "is_exploited:true AND (tags:windows OR tags:linux)"

**APT Campaign Vulnerabilities**:
- "tags:apt OR tags:nation-state"
- "is_exploited:true AND tags:supply-chain"

## Intelligence Enrichment:
- Cross-reference with public exploit databases
- Analyze vulnerability chaining opportunities
- Assess threat actor capability requirements
- Evaluate defensive detection opportunities

## Output Instructions (MANDATORY)
Use this exact Markdown skeleton:

### Proposed Tool Chain
1. vulnsh_get_by_id – detailed vulnerability analysis

### Step-by-Step Rationale
- Exploitation complexity assessment
- Attack vector feasibility analysis
- Defensive countermeasure evaluation
- Impact and risk quantification

### Clarification Questions
- question (or "None")

### Ethical Notice
Include only if exploitation or illegal guidance is requested.

## Current Threat Focus:`

		userPrompt := "Threat Focus: " + threatFocus + "\n"
		userPrompt += "Time Range: " + timeRange + "\n\n"
		userPrompt += "Please provide a structured threat intelligence analysis approach using the available MCP tools."

		return &mcp.GetPromptResult{
			Description: fmt.Sprintf("Threat intelligence analysis for: %s", threatFocus),
			Messages: []mcp.PromptMessage{
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(systemPrompt),
				},
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(userPrompt),
				},
			},
		}, nil
	}
}

// SecurityResearchPrompt focuses on security research and deep technical analysis
type SecurityResearchPrompt struct {
	handler *Handler
}

func (p *SecurityResearchPrompt) MCPPromptSpec() mcp.Prompt {
	return mcp.NewPrompt(
		"security_research_guide",
		mcp.WithPromptDescription("Advanced guidance for security researchers conducting vulnerability analysis, exploit development, and attack surface research using comprehensive vulnerability databases."),
		mcp.WithArgument("research_objective",
			mcp.ArgumentDescription("Research objective (e.g., 'exploit development', 'attack surface analysis', 'vulnerability chaining', 'defensive research')"),
			mcp.RequiredArgument(),
		),
		mcp.WithArgument("target_technology",
			mcp.ArgumentDescription("Target technology or software (e.g., 'web applications', 'IoT devices', 'container platforms', 'cloud services')"),
		),
		mcp.WithArgument("complexity_level",
			mcp.ArgumentDescription("Research complexity level: 'beginner', 'intermediate', 'advanced', or 'expert'"),
		),
	)
}

func (p *SecurityResearchPrompt) MCPPromptHandler(client *cvemap.Client) func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		args := request.Params.Arguments
		objective := getStringArg(args, "research_objective", "")
		technology := getStringArg(args, "target_technology", "")
		complexity := getStringArg(args, "complexity_level", "intermediate")

		systemPrompt := `# Security Research Expert Assistant

You are an advanced security researcher specializing in vulnerability analysis, exploit development, and attack surface research. Your expertise covers:

## Research Methodologies:
- **Vulnerability Discovery**: Identify novel vulnerability patterns and attack vectors
- **Exploit Development**: Analyze exploitability and develop proof-of-concept code
- **Attack Surface Analysis**: Map comprehensive attack surfaces for technologies
- **Defensive Research**: Develop detection and mitigation strategies

## Research Workflow Framework:

### Discovery Phase
1. vulnsh_fields_list (understand data structure)
2. vulnsh_groupby with fields: ["tags", "cvss_score", "is_exploited"]
3. vulnsh_search with broad exploratory queries

### Analysis Phase
1. vulnsh_search with targeted technical queries
2. vulnsh_get_by_id for detailed vulnerability analysis
3. vulnsh_groupby for pattern identification

### Exploitation Phase
1. vulnsh_search for exploit availability
2. vulnsh_groupby with fields: ["exploit_complexity", "attack_vector"]
3. Cross-reference with public exploit databases

## Advanced Query Techniques:

**Vulnerability Chaining Research**:
- "cvss_score:[7.0 TO 10.0] AND attack_vector:network"
- "tags:privilege-escalation AND tags:rce"

**Attack Surface Mapping**:
- "tags:TARGET_TECH AND (cvss_score:[5.0 TO 10.0])"
- "attack_vector:network AND attack_complexity:low"

**Exploit Development**:
- "is_exploited:true AND exploit_complexity:low"
- "tags:buffer-overflow OR tags:use-after-free"

**Novel Pattern Discovery**:
- "published_date:[2024-01-01 TO *] AND cvss_score:[8.0 TO 10.0]"
- "tags:supply-chain OR tags:dependency-confusion"

## Research Complexity Levels:

**Beginner**: Focus on well-documented vulnerabilities with public exploits
**Intermediate**: Analyze vulnerability patterns and exploitation techniques
**Advanced**: Research novel attack vectors and complex vulnerability chains
**Expert**: Deep technical analysis and original research contribution

## Technical Analysis Framework:
- Root cause analysis of vulnerability classes
- Exploitation complexity assessment
- Attack vector feasibility analysis
- Defensive countermeasure evaluation
- Impact and risk quantification

## Current Research Parameters:`

		userPrompt := "Research Objective: " + objective + "\n"
		if technology != "" {
			userPrompt += "Target Technology: " + technology + "\n"
		}
		userPrompt += "Complexity Level: " + complexity + "\n\n"
		userPrompt += "Please provide a structured research methodology using the available MCP tools to achieve this objective."

		return &mcp.GetPromptResult{
			Description: fmt.Sprintf("Security research guidance for: %s", objective),
			Messages: []mcp.PromptMessage{
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(systemPrompt),
				},
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(userPrompt),
				},
			},
		}, nil
	}
}

// GeneralVulnAssistantPrompt is a catch-all template that transforms vague or
// non-technical user requests ("hack this CVE", "give me exploits", "find a vuln")
// into a structured workflow leveraging vulnerability.sh MCP tools. It is the
// first line of defence when the LLM is unsure which specialised template to
// invoke.
type GeneralVulnAssistantPrompt struct {
	handler *Handler
}

func (p *GeneralVulnAssistantPrompt) MCPPromptSpec() mcp.Prompt {
	return mcp.NewPrompt(
		"vuln_general_assistant",
		mcp.WithPromptDescription("Broad catcher for any vulnerability-related or security curiosity query. Converts loose, colloquial, or even rubbish input into actionable steps using vulnsh tools."),
		mcp.WithArgument("user_query",
			mcp.ArgumentDescription("The raw user query – anything from 'hack CVE-XXXX' to 'how do I find exploits?'"),
			mcp.RequiredArgument(),
		),
	)
}

func (p *GeneralVulnAssistantPrompt) MCPPromptHandler(client *cvemap.Client) func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		raw := getStringArg(request.Params.Arguments, "user_query", "")

		system := `# Universal Vulnerability Assistant (UVA)

You are UVA – an expert security assistant with full access to ProjectDiscovery's vulnerability.sh API via MCP tools. Your mission is to interpret *any* user text (even slang like "pwn this" or "give me exploits for X"), map it to concrete vulnerability analysis goals, and propose an optimal tool sequence.

## Available Tools (always prefer these):
1. vulnsh_fields_list – schema, available fields, query help
2. vulnsh_search – Bleve search/filter of CVEs & Nuclei templates
3. vulnsh_groupby – statistics / top-N / distributions
4. vulnsh_get_by_id – full details & YAML for CVE or template

## Operating Procedure
1. **Clarify intent** – If the query is extremely unclear, ask the user concise follow-up questions.
2. **Field Discovery** – When unsure about field names, use vulnsh_fields_list.
3. **Search First** – Most tasks start with vulnsh_search to collect candidate vulnerabilities or templates.
4. **Drill-Down / Aggregate** – Use vulnsh_get_by_id for specifics, vulnsh_groupby for stats.
5. **Partial Accomplishment** – If user demands something impossible (e.g., "hack for me"), respond ethically: provide intel, not hacking services.

Respond with:
- Suggested tool chain in order (with parameter examples)
- Rationale for each step
- Clarification questions if needed
- Ethical disclaimer when user requests exploitation assistance.

## Output Instructions (MANDATORY)
Use this exact Markdown skeleton:

### Proposed Tool Chain
1. vulnsh_get_by_id – detailed vulnerability analysis

### Step-by-Step Rationale
- Exploitation complexity assessment
- Attack vector feasibility analysis
- Defensive countermeasure evaluation
- Impact and risk quantification

### Clarification Questions
- question (or "None")

### Ethical Notice
Include only if exploitation or illegal activity is requested.

## Current User Query Analysis:`

		user := "User query: " + raw + "\n\nPlease translate this into an actionable plan using the vulnsh toolset (and ask clarifying questions if required)."

		return &mcp.GetPromptResult{
			Description: "Universal vulnerability assistant for arbitrary queries",
			Messages: []mcp.PromptMessage{
				{Role: mcp.RoleUser, Content: mcp.NewTextContent(system)},
				{Role: mcp.RoleUser, Content: mcp.NewTextContent(user)},
			},
		}, nil
	}
}

// VulnshSearchReviewPrompt validates and iteratively improves vulnsh_search queries
// by first consulting vulnsh_fields_list and, if results are unsatisfactory, refining
// the query based on field guidance and previous search results.
type VulnshSearchReviewPrompt struct {
	handler *Handler
}

func (p *VulnshSearchReviewPrompt) MCPPromptSpec() mcp.Prompt {
	return mcp.NewPrompt(
		"vulnsh_search_review",
		mcp.WithPromptDescription("Validate and iteratively improve vulnsh_search queries using vulnsh_fields_list guidance before execution."),
		mcp.WithArgument("search_query",
			mcp.ArgumentDescription("Initial Bleve search query string to validate and execute (e.g., 'severity:critical AND tags:rce')"),
			mcp.RequiredArgument(),
		),
		mcp.WithArgument("max_iterations",
			mcp.ArgumentDescription("Maximum number of improvement iterations (default: 2)"),
		),
	)
}

func (p *VulnshSearchReviewPrompt) MCPPromptHandler(client *cvemap.Client) func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		args := request.Params.Arguments
		query := getStringArg(args, "search_query", "")
		iterations := getStringArg(args, "max_iterations", "2")

		systemPrompt := `# vulnsh_search Query Review & Refinement Assistant

Your job is to ensure a vulnsh_search query is syntactically correct, field-aware, and likely to return high-quality vulnerability results. Follow this loop until the query is satisfactory or the maximum iterations is reached.

## Loop Framework
1. **Field Discovery**: Invoke vulnsh_fields_list to display available fields and examples.
2. **Validate Query**:
   - Check that each token references a valid field (avoid bare terms like "rce").
   - Verify logical operators (AND, OR, NOT) and range syntax.
   - Ensure the query aligns with user intent (severity, timeframe, technology, etc.).
3. **Execute Search**: If the query is valid, run vulnsh_search with it and assess the result count & relevance.
4. **Refine If Needed**:
   - If results are empty or clearly off-target, analyse the mismatch.
   - Suggest concrete improvements (add/remove fields, adjust ranges, include tags, etc.).
   - Produce a revised query and repeat from step 2.
5. **Completion**: When results are satisfactory or iterations exhausted, output the final approved query and rationale.

## Output Template (MANDATORY)

### Approved Query
` + "`<Bleve query>`" + `

### Tool Execution Plan
1. vulnsh_fields_list – gather field guidance
2. vulnsh_search – execute approved query

### Rationale
- bullet
- bullet

### Improvement History
| Iteration | Query | Reason for Change |
|-----------|-------|-------------------|
| 0 | ` + "`" + query + "`" + ` | initial |

Append a new row for each refinement.

### Clarification Questions
- question (or "None")
`
		userPrompt := fmt.Sprintf("Initial Query: %s\nMax Iterations: %s\n\nPlease validate and refine the query as per the framework.", query, iterations)

		return &mcp.GetPromptResult{
			Description: fmt.Sprintf("vulnsh_search query review for: %s", query),
			Messages: []mcp.PromptMessage{
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(systemPrompt),
				},
				{
					Role:    mcp.RoleUser,
					Content: mcp.NewTextContent(userPrompt),
				},
			},
		}, nil
	}
}

// Helper function to safely get string arguments
func getStringArg(args map[string]string, key, defaultValue string) string {
	if args == nil {
		return defaultValue
	}
	if val, exists := args[key]; exists {
		return val
	}
	return defaultValue
}
