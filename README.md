# vulnsh - The Swiss Army Knife for Vulnerability Intelligence

> **Modern CLI for exploring CVE data with powerful search, filtering, and analysis capabilities**

<p align="center">
  <img src="static/cvemap.png" alt="vulnsh" width="200px">
</p>

## Quick Start

```bash
# 1. Get vulnsh
go install github.com/projectdiscovery/cvemap/cmd/vulnsh@latest

# 2. Explore commands (no API key needed for help)
vulnsh --help
vulnsh search --help

# 3. Set up your API key (free at https://cloud.projectdiscovery.io)
vulnsh auth

# 4. Start exploring vulnerabilities
vulnsh search apache
vulnsh id CVE-2021-44228
```

## What vulnsh Does

**Search vulnerabilities with precision:**
```bash
vulnsh search severity:critical is_remote:true
vulnsh search "apache OR nginx" --limit 20
vulnsh search cvss_score:>8.0 cve_created_at:2024
```

**Get detailed vulnerability info:**
```bash
vulnsh id CVE-2021-44228
vulnsh id CVE-2024-1234 --json
```

**Analyze vulnerability patterns:**
```bash
vulnsh analyze --fields severity
vulnsh analyze --fields affected_products.vendor
```

## Core Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `search` | Find vulnerabilities with advanced filters | `vulnsh search apache severity:high` |
| `id` | Get details for specific CVE | `vulnsh id CVE-2021-44228` |
| `analyze` | Aggregate data by fields | `vulnsh analyze -f severity` |
| `auth` | Configure API access | `vulnsh auth` |
| `version` | Show version info | `vulnsh version` |
| `healthcheck` | Test connectivity | `vulnsh healthcheck` |

## Essential Options

**Output formats:**
```bash
vulnsh search apache --json              # Machine-readable JSON
vulnsh search apache --output results.json  # Save to file
vulnsh search apache --silent            # Quiet output
```

**Search control:**
```bash
vulnsh search apache --limit 50          # Get 50 results
vulnsh search apache --sort-desc cvss_score  # Sort by CVSS score
vulnsh search apache --fields cve_id,severity  # Specific fields only
```

**Advanced search:**
```bash
vulnsh search --term-facets severity=5,tags=10 apache
vulnsh search --range-facets numeric:cvss_score:high:8:10 remote
```

## Common Search Patterns

**Find high-risk vulnerabilities:**
```bash
vulnsh search severity:critical is_remote:true is_kev:true
```

**Search by technology:**
```bash
vulnsh search apache                     # Apache vulnerabilities  
vulnsh search "apache OR nginx"          # Multiple technologies
vulnsh search affected_products.vendor:microsoft  # By vendor
```

**Filter by severity and scores:**
```bash
vulnsh search severity:high              # High severity
vulnsh search cvss_score:>7.0            # CVSS score above 7
vulnsh search epss_score:>0.8            # High EPSS score
```

**Time-based searches:**
```bash
vulnsh search cve_created_at:2024        # Published in 2024
vulnsh search cve_created_at:[2024-01-01 TO 2024-06-30]  # Date range
```

**Find exploitable vulnerabilities:**
```bash
vulnsh search is_poc:true                # Has proof of concept
vulnsh search is_kev:true                # Known exploited vulns
vulnsh search is_template:true           # Has Nuclei templates
```

## Useful Field Names

| Field | Description | Example Values |
|-------|-------------|----------------|
| `severity` | Vulnerability severity | `low`, `medium`, `high`, `critical` |
| `cvss_score` | CVSS score (0-10) | `7.5`, `>8.0`, `[7 TO 9]` |
| `cve_id` | CVE identifier | `CVE-2021-44228` |
| `is_remote` | Remotely exploitable | `true`, `false` |
| `is_kev` | Known exploited vuln | `true`, `false` |
| `is_poc` | Has proof of concept | `true`, `false` |
| `affected_products.vendor` | Vendor name | `apache`, `microsoft` |
| `affected_products.product` | Product name | `tomcat`, `windows` |
| `cve_created_at` | Publication date | `2024`, `2024-01-01` |

## Query Syntax

**Basic searches:**
```bash
vulnsh search apache                     # Simple term
vulnsh search "remote code execution"    # Phrase search
vulnsh search severity:critical          # Field search
```

**Boolean logic:**
```bash
vulnsh search apache AND nginx           # Both terms
vulnsh search apache OR nginx            # Either term  
vulnsh search apache NOT tomcat          # Exclude term
vulnsh search "(apache OR nginx) AND severity:high"  # Grouped
```

**Ranges and wildcards:**
```bash
vulnsh search cvss_score:>8.0            # Greater than
vulnsh search cvss_score:[7 TO 9]        # Range
vulnsh search apache*                    # Wildcard
```

## Configuration

**Set up authentication:**
```bash
vulnsh auth                              # Interactive setup
export PDCP_API_KEY="your-key-here"     # Environment variable
```

**Global options:**
```bash
vulnsh --json search apache              # JSON output
vulnsh --silent search apache            # No banner
vulnsh --no-pager search apache          # No paging
vulnsh --timeout 60s search apache       # Custom timeout
```

## Troubleshooting

**API key issues:**
```
Error: api key is required
→ Run: vulnsh auth
```

**Help commands requiring API key:**
```
Error: api key is required (when running vulnsh search --help)
→ This is a known limitation. Either:
  1. Set up API key first: vulnsh auth
  2. Use this documentation for command help
```

**No results:**
```bash
vulnsh search is_kev:true --limit 1      # Test with known results
vulnsh healthcheck                       # Check connectivity
```

**Large result sets:**
```bash
vulnsh search apache --limit 100         # Increase limit
vulnsh search apache --offset 100        # Pagination
vulnsh search --fields cve_id,severity apache  # Fewer fields
```

**Connection issues:**
```bash
vulnsh --timeout 60s search apache       # Increase timeout
vulnsh --proxy http://proxy:8080 search apache  # Use proxy
vulnsh --debug search apache             # Debug mode
```

## Getting Help

**Main help (no API key required):**
```bash
vulnsh --help                           # All commands overview
vulnsh version --disable-update-check   # Version info
```

**Command help (requires API key):**
```bash
vulnsh search --help                    # Search command help  
vulnsh id --help                        # ID command help
vulnsh analyze --help                   # Analyze command help
vulnsh search help                      # Detailed search fields
vulnsh analyze help                     # Available analyze fields
```

> **Note:** Currently, command-specific help requires API authentication. Run `vulnsh auth` first to set up your API key.

## Tips

- Start with broad searches, then narrow down with filters
- Use `--json` for scripting and automation
- Combine multiple filters for precise results
- Use `analyze` to understand data patterns
- Save frequently used queries as shell aliases

For advanced usage patterns and examples, see [USAGE.md](USAGE.md).