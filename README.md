<h1 align="center"> vulnx </h1>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/cvemap"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/cvemap"></a>
<a href="https://pkg.go.dev/github.com/projectdiscovery/cvemap/pkg/cvemap"><img src="https://img.shields.io/badge/go-reference-blue"></a>
<a href="https://github.com/projectdiscovery/cvemap/releases"><img src="https://img.shields.io/github/release/projectdiscovery/cvemap"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<h4 align="center"> Modern CLI for exploring vulnerability data with powerful search, filtering, and analysis capabilities </h4>

![image](https://github.com/user-attachments/assets/d60a1d43-27d8-4874-9459-046b7d8c633a)

## 🚀 Migration Notice

**vulnx is the next generation of cvemap** - we recommend upgrading to vulnx for the latest features and improvements.

> ⚠️ **Important**: cvemap uses an older API version that will be discontinued on **August 1, 2025**.

## Quick Start

```bash
# 1. Get vulnx
go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest

# 2. Explore commands (no API key needed for help)
vulnx --help
vulnx search --help

# 3. Set up your API key (required)
vulnx auth                              # Get free API key at https://cloud.projectdiscovery.io

# 4. Start exploring vulnerabilities
vulnx filters                          # See all available search fields
vulnx search apache
vulnx id CVE-2021-44228
```

## What vulnx Does

**Search vulnerabilities with precision:**
```bash
vulnx search "severity:critical && is_remote:true"
vulnx search "apache || nginx" --limit 20
vulnx search "cvss_score:>8.0 && cve_created_at:2024"
```

**Get detailed vulnerability info:**
```bash
vulnx id CVE-2021-44228
vulnx id CVE-2024-1234 --json
```

**Analyze vulnerability patterns:**
```bash
vulnx analyze --fields severity
vulnx analyze --fields affected_products.vendor
```

## Core Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `search` | Find vulnerabilities with advanced filters | `vulnx search "apache && severity:high"` |
| `id` | Get details for specific CVE | `vulnx id CVE-2021-44228` |
| `filters` | List all available search fields and filters | `vulnx filters` |
| `analyze` | Aggregate data by fields | `vulnx analyze -f severity` |
| `auth` | Configure API access | `vulnx auth` |
| `version` | Show version info | `vulnx version` |
| `healthcheck` | Test connectivity | `vulnx healthcheck` |

## Essential Options

**Output formats:**
```bash
vulnx search "apache" --json              # Machine-readable JSON
vulnx search "apache" --output results.json  # Save to file
vulnx search "apache" --silent            # Quiet output
```

**Search control:**
```bash
vulnx search "apache" --limit 50          # Get 50 results
vulnx search "apache" --sort-desc cvss_score  # Sort by CVSS score
vulnx search "apache" --fields cve_id,severity  # Specific fields only
```

**Advanced search:**
```bash
vulnx search --term-facets severity=5,tags=10 "apache"
vulnx search --range-facets numeric:cvss_score:high:8:10 "remote"
vulnx search --highlight "apache"            # Enable search highlighting
vulnx search --facet-size 20 "nginx"         # More facet buckets
vulnx search --detailed "xss"                # Detailed output like 'id' command
```

## Discovering Available Fields

**Explore what you can search on:**
```bash
vulnx filters                           # Show all available search fields
vulnx filters --json                    # Machine-readable field list
vulnx filters --output fields.json      # Save field info to file
```

The `filters` command shows detailed information about all searchable fields including:
- Field names and data types
- Descriptions and examples
- Whether fields support sorting and faceting
- Available enum values for specific fields
- Search analyzer types

**Example output:**
```
Field: severity
Data Type: string
Description: Vulnerability severity level (e.g., critical, high, medium, low, info)
Can Sort: Yes
Facet Possible: Yes
Search Analyzer: keyword-lower
Examples: severity:critical, severity:high
Enum Values: critical, high, medium, low, info, unknown

Total: 69 filters available
```

Use this command to discover new search possibilities and understand field syntax before building complex queries.

## Common Search Patterns

**Find high-risk vulnerabilities:**
```bash
vulnx search "severity:critical && is_remote:true && is_kev:true"
vulnx search "cvss_score:>8.0 && cve_created_at:>=2024"  # High CVSS from 2024
vulnx search "is_kev:true && age_in_days:<90"            # Recent KEV exploits
```

**Search by technology:**
```bash
vulnx search "apache"                     # Apache vulnerabilities
vulnx search "apache || nginx"          # Multiple technologies
vulnx search "affected_products.vendor:microsoft"  # By vendor
```

**Filter by severity and scores:**
```bash
vulnx search "severity:high"              # High severity
vulnx search "cvss_score:>7.0"            # CVSS score above 7
vulnx search "epss_score:>0.8"            # High EPSS score
```

**Time-based searches:**
```bash
vulnx search "cve_created_at:>=2024"      # Published in 2024 or later
vulnx search "cve_created_at:>=2024-01-01 && cve_created_at:<2024-07-01"  # First half of 2024
vulnx search "age_in_days:<30"            # Recent vulnerabilities (last 30 days)
```

**Find exploitable vulnerabilities:**
```bash
vulnx search "is_poc:true"                # Has proof of concept
vulnx search "is_kev:true"                # Known exploited vulns
vulnx search "is_template:true"           # Has Nuclei templates
vulnx search --detailed "log4j"          # Detailed analysis of specific vuln
```

## Filter Flags

### Filter Flags Reference

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--product` | `-p` | Filter by products | `--product apache,nginx` |
| `--vendor` | | Filter by vendors | `--vendor microsoft,oracle` |
| `--severity` | `-s` | Filter by severity | `--severity critical,high` |
| `--tags` | | Filter by tags | `--tags rce,injection` |
| `--cvss-score` | | Filter by CVSS score | `--cvss-score ">8.0"` |
| `--epss-score` | | Filter by EPSS score | `--epss-score ">0.8"` |
| `--vuln-age` | | Filter by age | `--vuln-age "<30"` |
| `--vuln-type` | | Filter by vulnerability type | `--vuln-type sql_injection` |
| `--kev-only` | | KEV vulnerabilities only | `--kev-only` |
| `--template` | `-t` | Has Nuclei templates | `--template` |
| `--poc` | | Has proof of concept | `--poc` |
| `--hackerone` | | HackerOne reported | `--hackerone` |
| `--remote-exploit` | | Remotely exploitable | `--remote-exploit` |
| `--vstatus` | | Filter by vuln status | `--vstatus confirmed` |


### Search Control Flags

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--detailed` | | Detailed output like 'id' | `--detailed` |
| `--highlight` | | Enable search highlighting | `--highlight` |
| `--limit` | `-n` | Number of results | `--limit 50` |
| `--offset` | | Pagination offset | `--offset 100` |
| `--sort-asc` | | Sort ascending | `--sort-asc cvss_score` |
| `--sort-desc` | | Sort descending | `--sort-desc cve_created_at` |
| `--fields` | | Select specific fields | `--fields cve_id,severity` |
| `--term-facets` | | Calculate term facets | `--term-facets severity=5` |
| `--range-facets` | | Calculate range facets | `--range-facets numeric:cvss_score:high:8:10` |
| `--facet-size` | | Facet bucket count | `--facet-size 20` |

**Product and vendor filtering:**
```bash
vulnx search --product apache,nginx     # Filter by products (searches both vendor and product fields)
vulnx search --vendor microsoft,oracle  # Filter by vendors only
vulnx search "NOT apache"               # Exclude products using query syntax
vulnx search "NOT affected_products.vendor:microsoft"  # Exclude vendors using query syntax
```

**Severity and scoring:**
```bash
vulnx search --severity critical,high   # Filter by severity
vulnx search "NOT severity:low"         # Exclude severities using query syntax
vulnx search --cvss-score ">8.0"        # Filter by CVSS score
vulnx search --epss-score ">0.8"        # Filter by EPSS score
vulnx search --vstatus confirmed         # Filter by status
vulnx search --vuln-age "<30"           # Recent vulnerabilities
```

**Exploit characteristics:**
```bash
vulnx search --kev-only                 # KEV vulnerabilities only
vulnx search --template                 # Has Nuclei templates
vulnx search --poc                      # Has proof of concept
vulnx search --hackerone                # HackerOne reported
vulnx search --remote-exploit           # Remotely exploitable
```

## Vulnerability ID Lookup

**Multiple input methods:**
```bash
# Single ID lookup
vulnx id CVE-2024-1234

# Multiple IDs (comma-separated)
vulnx id CVE-2024-1234,CVE-2024-5678,CVE-2023-9999

# Auto-detection from stdin (no 'id' command needed!)
echo "CVE-2024-1234" | vulnx
echo -e "CVE-2024-1234\nCVE-2024-5678" | vulnx

# File input
vulnx id --file ids.txt
```

**Batch processing:**
```bash
# JSON output for automation
vulnx id --json CVE-2024-1234 CVE-2024-5678

# Save to file
vulnx id --output vulns.json --file ids.txt

# Pipeline integration
cat report.txt | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' | vulnx id --json
```

## Useful Field Names

| Field | Description | Example Values |
|-------|-------------|----------------|
| `severity` | Vulnerability severity | `low`, `medium`, `high`, `critical` |
| `cvss_score` | CVSS score (0-10) | `7.5`, `>8.0`, `<9.0` |
| `cve_id` | CVE identifier | `CVE-2021-44228` |
| `is_remote` | Remotely exploitable | `true`, `false` |
| `is_kev` | Known exploited vuln | `true`, `false` |
| `is_poc` | Has proof of concept | `true`, `false` |
| `affected_products.vendor` | Vendor name | `apache`, `microsoft` |
| `affected_products.product` | Product name | `tomcat`, `windows` |
| `cve_created_at` | Publication date | `>=2024`, `>2024-01-01`, `<2023` |
| `age_in_days` | Days since publication | `<30`, `>365`, `<=90` |

## Query Syntax

**Basic searches:**
```bash
vulnx search "apache"                     # Simple term
vulnx search "remote code execution"    # Phrase search
vulnx search "severity:critical"          # Field search
```

**Boolean logic:**
```bash
vulnx search "apache && nginx"           # Both terms
vulnx search "apache || nginx"            # Either term
vulnx search "apache NOT tomcat"          # Exclude term
vulnx search "(apache || nginx) && severity:high"  # Grouped
```

**Ranges and wildcards:**
```bash
vulnx search "cvss_score:>8.0"            # Greater than
vulnx search "cvss_score:<9.0"            # Less than
vulnx search "cve_created_at:>=2024-01-01" # Date comparison
vulnx search "age_in_days:<30"            # Recent vulnerabilities
vulnx search "apache*"                    # Wildcard
```

## Date Queries

**Important**: Date fields require comparison operators (`>=`, `>`, `<`, `<=`).

**Single date comparisons:**
```bash
vulnx search "cve_created_at:>=2024"      # CVEs from 2024 onward
vulnx search "cve_created_at:<2024"       # CVEs before 2024
vulnx search "cve_created_at:>2024-06-01" # CVEs after June 1, 2024
```

**Date ranges:**
```bash
# CVEs from January 2024 only
vulnx search "cve_created_at:>=2024-01-01 && cve_created_at:<2024-02-01"

# High CVSS CVEs from 2024
vulnx search "cvss_score:>8.0 && cve_created_at:>=2024"

# Recent vulnerabilities (age-based)
vulnx search "age_in_days:<30"            # Last 30 days
vulnx search "age_in_days:>365"           # Older than 1 year
```

**Supported formats:**
- `2024` (year)
- `2024-01` (year-month)
- `2024-01-15` (full date)

## Configuration

**Set up authentication:**
```bash
vulnx auth                              # Interactive setup
vulnx auth --api-key YOUR_API_KEY       # Non-interactive (automation)
vulnx auth --test                       # Test current API key
export PDCP_API_KEY="your-key-here"     # Environment variable
```

**Authentication modes:**
- **Interactive**: `vulnx auth` - Guided setup with prompts
- **Non-interactive**: `vulnx auth --api-key KEY` - Perfect for automation/CI/CD
- **Test only**: `vulnx auth --test` - Validate current configuration

**Global options:**
```bash
vulnx --json search "apache"              # JSON output
vulnx --silent search "apache"            # No banner
vulnx --timeout 60s search "apache"       # Custom timeout
```

## Troubleshooting

**API key issues:**
```
Error: api key is required
→ Run: vulnx auth
```

**Automation/CI/CD setup:**
```bash
# Docker containers
vulnx auth --api-key "$SECRET_API_KEY"

# CI/CD pipelines
vulnx auth --api-key "${PDCP_API_KEY}"

# Kubernetes init containers
vulnx auth --api-key "$(cat /secrets/api-key)"

# Test authentication in scripts
vulnx auth --test && echo "Auth OK" || echo "Auth failed"
```

**Help commands requiring API key:**
```
Error: api key is required (when running vulnx search --help)
→ This is a known limitation. Either:
  1. Set up API key first: vulnx auth
  2. Use this documentation for command help
```

**No results:**
```bash
vulnx search "is_kev:true" --limit 1      # Test with known results
vulnx healthcheck                       # Check connectivity
```

**Large result sets:**
```bash
vulnx search "apache" --limit 100         # Increase limit
vulnx search "apache" --offset 100        # Pagination
vulnx search --fields cve_id,severity "apache"  # Fewer fields
```

**Connection issues:**
```bash
vulnx --timeout 60s search "apache"       # Increase timeout
vulnx --proxy http://proxy:8080 search "apache"  # Use proxy
vulnx --debug search "apache"             # Debug mode
```

## Getting Help

**Main help (no API key required):**
```bash
vulnx --help                           # All commands overview
vulnx version --disable-update-check   # Version info
```

**Command help (requires API key):**
```bash
vulnx search --help                    # Search command help
vulnx id --help                        # ID command help
vulnx filters --help                   # Filters command help
vulnx analyze --help                   # Analyze command help
vulnx filters                          # Show all searchable fields
vulnx search help                      # Detailed search fields
vulnx analyze help                     # Available analyze fields
```

> **Note:** Currently, command-specific help requires API authentication. Run `vulnx auth` first to set up your API key.

## Tips

- Use `vulnx filters` to discover all available search fields and their syntax
- Start with broad searches, then narrow down with filters
- Use `--json` for scripting and automation
- Combine multiple filters for precise results
- Use `analyze` to understand data patterns
- Save frequently used queries as shell aliases

For advanced usage patterns and examples, see [USAGE.md](USAGE.md).

## Development

For development setup, code quality checks, and contribution guidelines, see [DEVELOPMENT.md](DEVELOPMENT.md).

## License

vulnx is distributed under [MIT License](LICENSE).
