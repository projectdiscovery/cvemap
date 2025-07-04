# vulnsh - The Swiss Army Knife for Vulnerability Intel

<p align="center">
  <img src="static/cvemap.png" alt="vulnsh" width="300px">
</p>

**vulnsh** is a modern, powerful command-line interface for navigating and exploring vulnerability data from the ProjectDiscovery Vulnerability Database. It provides intuitive commands for searching, filtering, and analyzing CVE information with support for advanced faceted search, aggregations, and multiple output formats.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Commands](#commands)
  - [search](#search-command)
  - [id](#id-command)
  - [groupby](#groupby-command)
- [Global Flags](#global-flags)
- [Examples](#examples)
- [Output Formats](#output-formats)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## Features

- **🔍 Advanced Search**: Powerful Lucene-style query syntax with faceted search capabilities
- **📊 Aggregations**: Group vulnerabilities by any field using the `groupby` command
- **🎯 Precise Lookups**: Get detailed information for specific CVEs using the `id` command
- **🔄 Multiple Output Formats**: Support for both human-readable YAML and machine-readable JSON
- **📄 Pagination**: Handle large result sets with offset and limit controls
- **🎨 Rich Terminal Output**: Colorized YAML output with paging support
- **🔧 Flexible Configuration**: Extensive flag support for customizing behavior
- **📋 Comprehensive Help**: Detailed help system with dynamic field information

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/projectdiscovery/cvemap.git
cd cvemap

# Build vulnsh
make build-vulnsh

# Move to PATH (optional)
sudo mv vulnsh /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/projectdiscovery/cvemap/cmd/vulnsh@latest
```

## Configuration

vulnsh requires a ProjectDiscovery Cloud Platform (PDCP) API key to access the vulnerability database.

### Environment Variable

```bash
export PDCP_API_KEY="your-api-key-here"
```

### Getting an API Key

1. Sign up at [ProjectDiscovery Cloud Platform](https://cloud.projectdiscovery.io/)
2. Navigate to your dashboard
3. Generate a new API key
4. Export it as the `PDCP_API_KEY` environment variable

## Commands

### search Command

The `search` command provides powerful full-text and faceted search across the vulnerability database.

```bash
vulnsh search [query] [flags]
```

#### Search Flags

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--limit` | `-n` | Number of results to return | `--limit 50` |
| `--offset` | | Offset for pagination | `--offset 100` |
| `--sort-asc` | | Field to sort ascending | `--sort-asc cvss_score` |
| `--sort-desc` | | Field to sort descending | `--sort-desc cve_created_at` |
| `--fields` | | Fields to include in response | `--fields cve_id,severity,cvss_score` |
| `--term-facets` | | Term facets to calculate | `--term-facets severity=5,tags=10` |
| `--range-facets` | | Range facets to calculate | `--range-facets numeric:cvss_score:high:8:10` |
| `--highlight` | | Return search highlights | `--highlight` |
| `--facet-size` | | Number of facet buckets | `--facet-size 20` |

#### Search Examples

```bash
# Basic search for KEV vulnerabilities
vulnsh search is_kev:true

# Search with pagination
vulnsh search --limit 20 --offset 40 apache

# Search with sorting
vulnsh search --sort-desc cvss_score --limit 10 severity:critical

# Search with facets
vulnsh search --term-facets severity=5,tags=10 is_template:true

# Complex query with range facets
vulnsh search --range-facets numeric:cvss_score:high:8:10 "apache AND remote"
```

### id Command

Get detailed information about a specific vulnerability by its ID.

```bash
vulnsh id <vulnerability-id>
```

#### ID Examples

```bash
# Get details for a specific CVE
vulnsh id CVE-2024-1234

# Get details with JSON output
vulnsh id --json CVE-2024-1234

# Save details to file
vulnsh id --output vuln-details.json CVE-2024-1234
```

### groupby Command

Perform GROUP BY-style aggregations on vulnerability data using term facets.

```bash
vulnsh groupby [flags]
```

#### Groupby Flags

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--fields` | `-f` | Fields to group by (required) | `--fields severity,tags` |
| `--facet-size` | | Number of buckets per facet | `--facet-size 15` |
| `--query` | `-q` | Filter query before grouping | `--query "is_template:true"` |

#### Groupby Examples

```bash
# Group by severity
vulnsh groupby --fields severity

# Group by multiple fields
vulnsh groupby --fields severity,tags --facet-size 5

# Group with pre-filtering
vulnsh groupby --fields affected_products.vendor --query "is_kev:true"
```

## Global Flags

These flags are available for all commands:

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--json` | `-j` | Output raw JSON | `false` |
| `--output` | `-o` | Write output to file | |
| `--silent` | | Suppress banner and non-essential output | `false` |
| `--verbose` | `-v` | Enable verbose logging | `false` |
| `--debug` | `-d` | Enable debug logging | `false` |
| `--no-pager` | | Disable pager for output | `false` |
| `--proxy` | | HTTP proxy URL | |
| `--timeout` | | HTTP request timeout | `30s` |
| `--debug-req` | | Dump HTTP requests | `false` |
| `--debug-resp` | | Dump HTTP responses | `false` |

## Examples

### Basic Usage

```bash
# Search for critical vulnerabilities
vulnsh search severity:critical

# Get all Apache vulnerabilities from 2024
vulnsh search apache AND cve_created_at:2024

# Find remote exploitable vulnerabilities
vulnsh search is_remote:true AND is_poc:true
```

### Advanced Queries

```bash
# Search with complex Boolean logic
vulnsh search "(apache OR nginx) AND severity:high AND is_kev:true"

# Search with CVSS score range
vulnsh search cvss_score:>8.0 AND cvss_score:<=10.0

# Search by specific fields
vulnsh search --fields cve_id,severity,cvss_score,description severity:critical
```

### Faceted Search

```bash
# Get severity distribution
vulnsh search --term-facets severity=10 is_template:true

# Get vulnerability counts by year
vulnsh search --range-facets date:cve_created_at:2020:2024 

# Multiple facets with filtering
vulnsh search --term-facets severity=5,tags=10 \
              --range-facets numeric:cvss_score:high:8:10 \
              is_remote:true
```

### Aggregations

```bash
# Group vulnerabilities by severity
vulnsh groupby -f severity

# Group by vendor and product
vulnsh groupby -f affected_products.vendor,affected_products.product

# Group with filtering
vulnsh groupby -f severity -q "cve_created_at:2024 AND is_kev:true"
```

### Output Formats

```bash
# Human-readable YAML (default)
vulnsh search apache

# Machine-readable JSON
vulnsh search --json apache

# Save to file
vulnsh search --output apache-vulns.json apache

# Suppress banner for scripting
vulnsh search --silent --json apache
```

## Output Formats

### YAML Output (Default)

vulnsh provides colorized, human-readable YAML output by default:

```yaml
count: 1247
vulnerabilities:
  - cve_id: CVE-2024-1234
    severity: critical
    cvss_score: 9.8
    description: "Remote code execution vulnerability..."
    # ... more fields
```

### JSON Output

Use `--json` flag for machine-readable JSON output:

```json
{
  "count": 1247,
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-1234",
      "severity": "critical",
      "cvss_score": 9.8,
      "description": "Remote code execution vulnerability..."
    }
  ]
}
```

## Advanced Usage

### Pagination

Handle large result sets with pagination:

```bash
# Get first 50 results
vulnsh search --limit 50 apache

# Get next 50 results
vulnsh search --limit 50 --offset 50 apache

# Get results 201-250
vulnsh search --limit 50 --offset 200 apache
```

### Field Selection

Optimize payload size by selecting specific fields:

```bash
# Only get essential fields
vulnsh search --fields cve_id,severity,cvss_score apache

# Get all fields (default behavior)
vulnsh search apache
```

### Sorting

Sort results by any sortable field:

```bash
# Sort by CVSS score (descending)
vulnsh search --sort-desc cvss_score apache

# Sort by creation date (ascending)
vulnsh search --sort-asc cve_created_at apache
```

### Proxy Support

Use vulnsh behind a proxy:

```bash
# HTTP proxy
vulnsh --proxy http://proxy.example.com:8080 search apache

# HTTPS proxy
vulnsh --proxy https://proxy.example.com:8080 search apache
```

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Enable debug logging
vulnsh --debug search apache

# Dump HTTP requests and responses
vulnsh --debug-req --debug-resp search apache
```

## Troubleshooting

### Common Issues

#### Authentication Error

```
Error: unauthorized: invalid or missing API key
```

**Solution**: Ensure your PDCP API key is properly set:
```bash
export PDCP_API_KEY="your-api-key-here"
```

#### Connection Timeout

```
Error: request failed: context deadline exceeded
```

**Solution**: Increase timeout or check network connectivity:
```bash
vulnsh --timeout 60s search apache
```

#### Large Result Sets

For very large result sets, consider:
- Using pagination with `--limit` and `--offset`
- Filtering with more specific queries
- Using `--fields` to reduce payload size

#### Output File Exists

```
Error: Output file already exists: results.json
```

**Solution**: vulnsh prevents accidental overwrites. Remove the existing file first:
```bash
rm results.json
vulnsh search --output results.json apache
```

### Getting Help

```bash
# General help
vulnsh --help

# Command-specific help
vulnsh search --help
vulnsh id --help
vulnsh groupby --help

# Detailed search help with available fields
vulnsh search help
```

## Query Syntax

vulnsh supports Lucene-style query syntax:

### Basic Queries

```bash
# Simple term search
vulnsh search apache

# Phrase search
vulnsh search "remote code execution"

# Field-specific search
vulnsh search severity:critical
```

### Boolean Operators

```bash
# AND operator
vulnsh search apache AND nginx

# OR operator
vulnsh search apache OR nginx

# NOT operator
vulnsh search apache NOT nginx

# Grouping with parentheses
vulnsh search "(apache OR nginx) AND severity:high"
```

### Range Queries

```bash
# Numeric ranges
vulnsh search cvss_score:>8.0
vulnsh search cvss_score:[7.0 TO 9.0]

# Date ranges
vulnsh search cve_created_at:2024
vulnsh search cve_created_at:[2024-01-01 TO 2024-12-31]
```

### Wildcard Queries

```bash
# Wildcard matching
vulnsh search apache*
vulnsh search *injection*

# Single character wildcard
vulnsh search apach?
```

## Common Field Names

Here are some commonly used field names for queries:

- `cve_id` - CVE identifier
- `severity` - Vulnerability severity (low, medium, high, critical)
- `cvss_score` - CVSS score (0.0-10.0)
- `description` - Vulnerability description
- `is_kev` - Known Exploited Vulnerability (true/false)
- `is_remote` - Remotely exploitable (true/false)
- `is_poc` - Proof of concept available (true/false)
- `is_template` - Nuclei template available (true/false)
- `cve_created_at` - CVE creation date
- `affected_products.vendor` - Affected product vendor
- `affected_products.product` - Affected product name
- `tags` - Associated tags

For a complete list of available fields, use:
```bash
vulnsh search help
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 🐛 Report bugs: [GitHub Issues](https://github.com/projectdiscovery/cvemap/issues)
- 💬 Get help: [Discord Community](https://discord.gg/projectdiscovery)
- 📖 Documentation: [docs.projectdiscovery.io](https://docs.projectdiscovery.io)
- 🔗 Website: [projectdiscovery.io](https://projectdiscovery.io)