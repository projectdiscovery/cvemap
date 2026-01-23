# vulnx Advanced Usage Guide

> **Master vulnx to efficiently discover, analyze, and track vulnerabilities**

## Quick Reference

| Task | Command |
|------|---------|
| **Find recent critical vulns** | `vulnx search "severity:critical && cve_created_at:2024"` |
| **Get Apache RCE vulns** | `vulnx search "apache && 'remote code execution'"` |
| **High CVSS with exploits** | `vulnx search "cvss_score:>8.0 && is_poc:true"` |
| **Known exploited vulns** | `vulnx search "is_kev:true"` |
| **Analyze by vendor** | `vulnx analyze -f affected_products.vendor` |

## Vulnerability ID Lookup

### Multiple Input Methods

The `vulnx id` command supports flexible input methods:

```bash
# Single ID lookup
vulnx id CVE-2024-1234

# File input
vulnx id --file ids.txt

# Comma-separated IDs (directly in arguments)
vulnx id CVE-2024-1234,CVE-2024-5678,CVE-2023-9999
```

### Auto-Detection Feature

vulnx now intelligently detects CVE IDs from stdin and automatically routes to the `id` command:

```bash
# Smart detection from mixed content
echo "Critical vulnerabilities found: CVE-2024-1234, CVE-2024-5678" | vulnx

# Works with any input format
echo "CVE-2024-1234,CVE-2024-5678,CVE-2023-9999" | vulnx

# Global flags work with auto-detection
echo "CVE-2024-1234" | vulnx --json
echo "CVE-2024-1234" | vulnx --output results.json --silent
```

### File Format Support

Create input files with flexible formatting:

```bash
# Line-by-line format
cat > vuln_ids.txt << 'EOF'
CVE-2024-1234
CVE-2024-5678
CVE-2023-9999
EOF
```

### Batch Processing Features

```bash
# JSON output for automation
vulnx id --json --file ids.txt > results.json

# Single ID as object, multiple as array
vulnx id --json CVE-2024-1234                    # Returns object
vulnx id --json CVE-2024-1234 CVE-2024-5678     # Returns array

# Comma-separated IDs
vulnx id --json CVE-2024-1234,CVE-2024-5678,CVE-2023-9999  # Returns array

# Save to file
vulnx id --output vulnerabilities.json --file ids.txt

# Handle errors gracefully
vulnx id --file ids.txt  # Continues processing if some IDs fail
```

### Integration Patterns

```bash
# Pipeline integration
cat vulnerability_report.txt | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' | vulnx id --json

# Incident response workflow
echo "CVE-2021-44228" | vulnx id | grep -A5 "CVSS:"

# Bulk validation
vulnx id --file cve_list.txt --json | jq '.[] | .cve_id + ": " + .severity'
```

## Search Strategies

### Start Broad, Filter Down

```bash
# 1. Start with technology
vulnx search "apache"

# 2. Add severity filter
vulnx search "apache && severity:high"

# 3. Add time constraint
vulnx search "apache && severity:high && cve_created_at:2024"

# 4. Focus on exploitable
vulnx search "apache && severity:high && cve_created_at:2024 && is_remote:true"
```

### Technology Stack Assessment

```bash
# Web stack vulnerabilities
vulnx search "(apache || nginx || tomcat) && severity:high"
vulnx search "affected_products.vendor:apache" --limit 100

# Database vulnerabilities
vulnx search "(mysql || postgresql || mongodb) && severity:critical"
vulnx search "affected_products.product:mysql && cve_created_at:2024"

# Framework vulnerabilities
vulnx search "(spring || django || rails) && is_remote:true"
```

### Threat Intelligence Workflows

**Find trending vulnerabilities:**
```bash
vulnx search "age_in_days:<365 && is_kev:true"
vulnx search "epss_score:>0.9" --sort-desc cve_created_at
```

**Active exploitation tracking:**
```bash
vulnx search "is_kev:true" --sort-desc cve_created_at --limit 20
vulnx search "is_poc:true && epss_score:>0.8" --sort-desc epss_score
```

**Zero-day monitoring:**
```bash
vulnx search "cve_created_at:2024 && cvss_score:>9.0" --limit 10
vulnx search "age_in_days:<30 && severity:critical"
```

## Advanced Filtering

### Temporal Analysis

```bash
# Recent high-impact vulnerabilities
vulnx search "age_in_days:<7 && severity:critical"
vulnx search "age_in_days:<90"

# Historical vulnerability patterns
vulnx search "cve_created_at:2023" --term-facets severity=10
vulnx analyze -f severity -q "cve_created_at:2023"

# Quarterly assessments
vulnx search "age_in_days:<365" --limit 1000
```

### Risk-Based Prioritization

```bash
# Critical + Exploitable + Remote
vulnx search "severity:critical && is_remote:true && is_poc:true"

# High CVSS + EPSS scores
vulnx search "cvss_score:>8.0 && epss_score:>0.7"

# CISA KEV vulnerabilities
vulnx search "is_kev:true" --sort-desc cve_created_at

# Template availability (for testing)
vulnx search "is_template:true && severity:high" --limit 50
```

### Vendor-Specific Intelligence

```bash
# Microsoft security patches
vulnx search "affected_products.vendor:microsoft && severity:critical"
vulnx search "affected_products.vendor:microsoft && cve_created_at:2024"

# Apache ecosystem
vulnx search "affected_products.vendor:apache" --term-facets severity=5
vulnx analyze -f affected_products.product -q "affected_products.vendor:apache"

# Open source project monitoring
vulnx search "is_oss:true && severity:high && cve_created_at:2024"
```

## Advanced Filter Usage

### Exclusion Filters

```bash
# Exclude specific products while searching
vulnx search --exclude-product apache,nginx "web server"
vulnx search --exclude-vendor microsoft,oracle "database"
vulnx search --exclude-severity low,medium "remote"

```

### CPE-Based Filtering

```bash
# Precise product matching with CPE
vulnx search --cpe "cpe:2.3:a:apache:*" "cve_created_at:2024"
vulnx search --cpe "cpe:2.3:o:microsoft:windows:*" "severity:critical"
vulnx search --cpe "cpe:2.3:a:*:wordpress:*" "is_remote:true"

# Combine CPE with other filters
vulnx search --cpe "cpe:2.3:a:apache:tomcat:*" --severity critical,high
```

### Status and Age Filtering

```bash
# Vulnerability status filtering
vulnx search --vstatus confirmed "severity:critical"
vulnx search --vstatus new "cve_created_at:2024"
vulnx search --vstatus modified "is_kev:true"

# Age-based filtering with operators
vulnx search --vuln-age "<7" "severity:critical"     # Last week
vulnx search --vuln-age ">365" "is_poc:true"         # Older than a year
vulnx search --vuln-age "30" "is_template:true"      # Exactly 30 days
vulnx search --vuln-age "<30" --kev-only             # Recent KEV vulns
```

### Advanced Search Options

```bash
# Enhanced output and highlighting
vulnx search --detailed "log4j"                      # Detailed like 'id' command
vulnx search --highlight "injection"                 # Highlight search terms
vulnx search --facet-size 25 --term-facets severity=10 "apache"

# Complex field selection and sorting
vulnx search --fields cve_id,severity,cvss_score,epss_score "apache"
vulnx search --sort-desc cvss_score --limit 50 "critical"
vulnx search --sort-asc cve_created_at "is_kev:true"
```

### Combined Filter Examples

```bash
# Multi-dimensional filtering
vulnx search --product apache,nginx --severity critical,high --vuln-age "<30"
vulnx search --vendor microsoft,oracle --exclude-severity low --kev-only
vulnx search --cpe "cpe:2.3:a:*:*:*" --exclude-product apache,tomcat --remote-exploit

# Complex filtering combinations
vulnx search \
  --product apache,nginx,mysql \
  --exclude-vendor microsoft,oracle \
  --severity critical,high \
  --vuln-age "<14" \
  --kev-only \
  --template
```

## Data Analysis Workflows

### Vulnerability Landscape Analysis

```bash
# Overall severity distribution
vulnx analyze -f severity

# Vendor risk assessment
vulnx analyze -f affected_products.vendor --facet-size 20

# Product vulnerability counts
vulnx analyze -f affected_products.product -q "severity:critical"

# CVE publication trends
vulnx search "cve_created_at:2024" --term-facets severity=10,tags=15
```

### Focused Assessments

```bash
# Web application security
vulnx analyze -f affected_products.product -q "is_remote:true"
vulnx search "web application && severity:high" --limit 100

# Infrastructure components
vulnx search "(router || firewall || switch)" --limit 50
vulnx analyze -f affected_products.vendor -q "affected_products.product:router"

# Cloud service vulnerabilities
vulnx search "(aws || azure || gcp) && severity:high"
vulnx search "affected_products.vendor:amazon && cve_created_at:2024"
```

## Automation & Scripting

### JSON Output for Processing

```bash
# Daily vulnerability feed
vulnx search "age_in_days:1" --json --silent > daily_vulns.json

# Critical vulnerability alerts
vulnx search "severity:critical && is_kev:true" --json --silent | \
  jq '.vulnerabilities[] | {cve_id, cvss_score, description}'

# Vendor-specific reports
vulnx search "affected_products.vendor:apache" --json --silent | \
  jq '.vulnerabilities | group_by(.severity) | length'
```

### Monitoring Scripts

**Check for new critical vulnerabilities:**
```bash
#!/bin/bash
# check_new_criticals.sh
NEW_CRITICALS=$(vulnx search "age_in_days:1 && severity:critical" --json --silent | \
                jq -r '.count')
if [ "$NEW_CRITICALS" -gt 0 ]; then
  echo "Alert: $NEW_CRITICALS new critical vulnerabilities found"
  vulnx search "age_in_days:1 && severity:critical" --json --silent
fi
```

**Technology stack monitoring:**
```bash
#!/bin/bash
# monitor_stack.sh
TECHNOLOGIES=("apache" "nginx" "mysql" "postgresql")
for tech in "${TECHNOLOGIES[@]}"; do
  echo "=== $tech vulnerabilities ==="
  vulnx search "$tech && age_in_days:7" --silent --limit 5
done
```

### Data Export Workflows

```bash
# Export to CSV-friendly format
vulnx search "severity:critical" --json --silent | \
  jq -r '.vulnerabilities[] | [.cve_id, .severity, .cvss_score] | @csv'

# Generate reports with specific fields
vulnx search "apache" --fields cve_id,severity,cvss_score,description \
  --json --output apache_report.json

# Batch processing multiple queries
for severity in critical high medium; do
  vulnx search "severity:$severity && cve_created_at:2024" \
    --json --output "vulns_$severity.json"
done
```

## Performance Optimization

### Efficient Queries

```bash
# Use specific fields to reduce payload
vulnx search "apache" --fields cve_id,severity,cvss_score --limit 1000

# Paginate large result sets
vulnx search "apache" --limit 100 --offset 0    # First 100
vulnx search "apache" --limit 100 --offset 100  # Next 100

# Filter early to reduce results
vulnx search "apache && severity:critical"  # Better than filtering later
```

### Caching Strategies

```bash
# Cache frequently used data
vulnx search "is_kev:true" --json --output kev_cache.json
vulnx analyze -f severity --json --output severity_stats.json

# Daily data snapshots
DATE=$(date +%Y-%m-%d)
vulnx search "cve_created_at:$DATE" --json --output "vulns_$DATE.json"
```

## Integration Patterns

### CI/CD Pipeline Integration

```bash
# Vulnerability scanning in pipelines
vulnx search "affected_products.product:docker" --json --silent | \
  jq '.count' | xargs -I {} echo "Found {} Docker vulnerabilities"

# Baseline security checks
vulnx search "(apache || nginx) && severity:critical" --count-only
```

### Security Monitoring Integration

```bash
# SIEM data enrichment
vulnx id CVE-2021-44228 --json --silent | \
  jq '{cve_id, severity, cvss_score, is_kev, is_poc}'

# Threat intelligence feeds
vulnx search "is_kev:true && age_in_days:30" --json --silent | \
  jq '.vulnerabilities[] | {cve_id, epss_score, cve_created_at}'
```

### Notification Workflows

```bash
# Slack notifications for critical vulnerabilities
CRITICALS=$(vulnx search "severity:critical && age_in_days:1" --json --silent)
if [ "$(echo $CRITICALS | jq '.count')" -gt 0 ]; then
  echo $CRITICALS | jq -r '"New critical vulnerabilities: " + (.count | tostring)'
fi
```

## Query Optimization Tips

### Effective Field Usage

```bash
# Target specific vendors/products
vulnx search "affected_products.vendor:microsoft"
vulnx search "affected_products.product:windows"

# Combine multiple criteria efficiently
vulnx search "severity:critical && is_remote:true && is_poc:true"

# Use comparison operators for scores
vulnx search "cvss_score:>8.0"  # Greater than 8.0
vulnx search "cvss_score:<9.0"  # Less than 9.0
```

### Faceting for Analysis

```bash
# Understand data distribution before detailed searches
vulnx search "apache" --term-facets severity=10,tags=5

# Multi-dimensional analysis
vulnx search --term-facets severity=5,affected_products.vendor=10 \
  --range-facets numeric:cvss_score:high:8:10

# Time-based faceting
vulnx search --range-facets date:cve_created_at:2024:2024-01:2024-12
```

## Common Patterns & Use Cases

### Security Research

```bash
# Find vulnerability families
vulnx search "'buffer overflow' && severity:high"
vulnx search "description:'SQL injection'" --limit 100

# Exploitation research
vulnx search "is_poc:true && cvss_score:>9.0" --sort-desc epss_score
vulnx search "tags:rce && is_template:true"
```

### Compliance & Reporting

```bash
# Generate compliance reports
vulnx search "affected_products.vendor:microsoft && cve_created_at:2024" \
  --output microsoft_2024_vulns.json

# Risk assessment data
vulnx analyze -f severity -q "is_remote:true"
vulnx search "severity:critical" --fields cve_id,cvss_score,epss_score
```

### Incident Response

```bash
# Check if vulnerability is known exploited
vulnx id CVE-2021-44228 --json | jq '.is_kev'

# Find related vulnerabilities
vulnx search "affected_products.vendor:apache && 'log4j'"
vulnx search "tags:log4j" --sort-desc cvss_score

# Impact assessment
vulnx search "affected_products.product:log4j && is_remote:true"
```

## Troubleshooting Advanced Usage

### Performance Issues

```bash
# Debug slow queries
vulnx --debug search "complex_query_here"

# Check network connectivity
vulnx healthcheck --verbose

# Optimize large result sets
vulnx search "broad_query" --fields cve_id --limit 10  # Test first
```

### Data Quality

```bash
# Verify field names and values
vulnx search help  # See available fields (requires API key)

# Test query syntax
vulnx search "test:value" --limit 1  # Verify syntax works

# Validate data ranges
vulnx search "cvss_score:>0" --limit 1  # Check valid ranges
```

### API Limits & Rate Limiting

```bash
# Implement delays in scripts
vulnx search "query1" && sleep 1 && vulnx search "query2"

# Use batch operations efficiently
vulnx search "large_query" --limit 1000 --output batch1.json
```

## Best Practices Summary

### Query Construction
- **Start broad, filter progressively** - Begin with general terms, add constraints
- **Use specific fields** - `affected_products.vendor:apache` vs. generic `apache`
- **Combine filters logically** - `severity:critical && is_remote:true`
- **Use comparison operators** - `cvss_score:>8` or `cvss_score:<9` for score filtering

### Data Management
- **Cache frequent queries** - Save commonly used results as JSON files
- **Use appropriate output formats** - JSON for automation, YAML for reading
- **Implement pagination** - Handle large datasets with `--limit` and `--offset`
- **Select relevant fields** - Use `--fields` to reduce payload size

### Automation
- **Silent mode for scripts** - Use `--silent` to suppress banners
- **Error handling** - Check exit codes and JSON structure
- **Rate limiting awareness** - Add delays between bulk operations
- **Structured output** - Parse JSON with `jq` for processing

---

Remember: Start simple, iterate, and build complexity as needed. Use `vulnx healthcheck` to verify connectivity, and always test queries with small limits before running large searches.
