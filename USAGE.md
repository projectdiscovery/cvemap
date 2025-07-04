# vulnsh Advanced Usage Guide

> **Master vulnsh to efficiently discover, analyze, and track vulnerabilities**

## Quick Reference

| Task | Command |
|------|---------|
| **Find recent critical vulns** | `vulnsh search severity:critical cve_created_at:2024` |
| **Get Apache RCE vulns** | `vulnsh search apache "remote code execution"` |
| **High CVSS with exploits** | `vulnsh search cvss_score:>8.0 is_poc:true` |
| **Known exploited vulns** | `vulnsh search is_kev:true` |
| **Analyze by vendor** | `vulnsh groupby -f affected_products.vendor` |

## Search Strategies

### Start Broad, Filter Down

```bash
# 1. Start with technology
vulnsh search apache

# 2. Add severity filter  
vulnsh search apache severity:high

# 3. Add time constraint
vulnsh search apache severity:high cve_created_at:2024

# 4. Focus on exploitable
vulnsh search apache severity:high cve_created_at:2024 is_remote:true
```

### Technology Stack Assessment

```bash
# Web stack vulnerabilities
vulnsh search "(apache OR nginx OR tomcat)" severity:high
vulnsh search affected_products.vendor:apache --limit 100

# Database vulnerabilities  
vulnsh search "(mysql OR postgresql OR mongodb)" severity:critical
vulnsh search affected_products.product:mysql cve_created_at:2024

# Framework vulnerabilities
vulnsh search "(spring OR django OR rails)" is_remote:true
```

### Threat Intelligence Workflows

**Find trending vulnerabilities:**
```bash
vulnsh search cve_created_at:[2024-01-01 TO 2024-12-31] is_kev:true
vulnsh search epss_score:>0.9 --sort-desc cve_created_at
```

**Active exploitation tracking:**
```bash
vulnsh search is_kev:true --sort-desc cve_created_at --limit 20
vulnsh search is_poc:true epss_score:>0.8 --sort-desc epss_score
```

**Zero-day monitoring:**
```bash
vulnsh search cve_created_at:2024 cvss_score:>9.0 --limit 10
vulnsh search age_in_days:<30 severity:critical
```

## Advanced Filtering

### Temporal Analysis

```bash
# Recent high-impact vulnerabilities
vulnsh search age_in_days:<7 severity:critical
vulnsh search cve_created_at:[2024-11-01 TO 2024-11-30]

# Historical vulnerability patterns
vulnsh search cve_created_at:2023 --term-facets severity=10
vulnsh groupby -f severity -q "cve_created_at:2023"

# Quarterly assessments
vulnsh search cve_created_at:[2024-01-01 TO 2024-03-31] --limit 1000
```

### Risk-Based Prioritization

```bash
# Critical + Exploitable + Remote
vulnsh search severity:critical is_remote:true is_poc:true

# High CVSS + EPSS scores
vulnsh search cvss_score:>8.0 epss_score:>0.7

# CISA KEV vulnerabilities
vulnsh search is_kev:true --sort-desc cve_created_at

# Template availability (for testing)
vulnsh search is_template:true severity:high --limit 50
```

### Vendor-Specific Intelligence

```bash
# Microsoft security patches
vulnsh search affected_products.vendor:microsoft severity:critical
vulnsh search affected_products.vendor:microsoft cve_created_at:2024

# Apache ecosystem
vulnsh search affected_products.vendor:apache --term-facets severity=5
vulnsh groupby -f affected_products.product -q "affected_products.vendor:apache"

# Open source project monitoring
vulnsh search is_oss:true severity:high cve_created_at:2024
```

## Data Analysis Workflows

### Vulnerability Landscape Analysis

```bash
# Overall severity distribution
vulnsh groupby -f severity

# Vendor risk assessment
vulnsh groupby -f affected_products.vendor --facet-size 20

# Product vulnerability counts
vulnsh groupby -f affected_products.product -q "severity:critical"

# CVE publication trends
vulnsh search cve_created_at:2024 --term-facets severity=10,tags=15
```

### Focused Assessments

```bash
# Web application security
vulnsh groupby -f affected_products.product -q "is_remote:true"
vulnsh search "web application" severity:high --limit 100

# Infrastructure components
vulnsh search "(router OR firewall OR switch)" --limit 50
vulnsh groupby -f affected_products.vendor -q "affected_products.product:router"

# Cloud service vulnerabilities
vulnsh search "(aws OR azure OR gcp)" severity:high
vulnsh search affected_products.vendor:amazon cve_created_at:2024
```

## Automation & Scripting

### JSON Output for Processing

```bash
# Daily vulnerability feed
vulnsh search age_in_days:1 --json --silent > daily_vulns.json

# Critical vulnerability alerts
vulnsh search severity:critical is_kev:true --json --silent | \
  jq '.vulnerabilities[] | {cve_id, cvss_score, description}'

# Vendor-specific reports
vulnsh search affected_products.vendor:apache --json --silent | \
  jq '.vulnerabilities | group_by(.severity) | length'
```

### Monitoring Scripts

**Check for new critical vulnerabilities:**
```bash
#!/bin/bash
# check_new_criticals.sh
NEW_CRITICALS=$(vulnsh search age_in_days:1 severity:critical --json --silent | \
                jq -r '.count')
if [ "$NEW_CRITICALS" -gt 0 ]; then
  echo "Alert: $NEW_CRITICALS new critical vulnerabilities found"
  vulnsh search age_in_days:1 severity:critical --json --silent
fi
```

**Technology stack monitoring:**
```bash
#!/bin/bash
# monitor_stack.sh
TECHNOLOGIES=("apache" "nginx" "mysql" "postgresql")
for tech in "${TECHNOLOGIES[@]}"; do
  echo "=== $tech vulnerabilities ==="
  vulnsh search "$tech" age_in_days:7 --silent --limit 5
done
```

### Data Export Workflows

```bash
# Export to CSV-friendly format
vulnsh search severity:critical --json --silent | \
  jq -r '.vulnerabilities[] | [.cve_id, .severity, .cvss_score] | @csv'

# Generate reports with specific fields
vulnsh search apache --fields cve_id,severity,cvss_score,description \
  --json --output apache_report.json

# Batch processing multiple queries
for severity in critical high medium; do
  vulnsh search severity:$severity cve_created_at:2024 \
    --json --output "vulns_$severity.json"
done
```

## Performance Optimization

### Efficient Queries

```bash
# Use specific fields to reduce payload
vulnsh search apache --fields cve_id,severity,cvss_score --limit 1000

# Paginate large result sets
vulnsh search apache --limit 100 --offset 0    # First 100
vulnsh search apache --limit 100 --offset 100  # Next 100

# Filter early to reduce results
vulnsh search apache severity:critical  # Better than filtering later
```

### Caching Strategies

```bash
# Cache frequently used data
vulnsh search is_kev:true --json --output kev_cache.json
vulnsh groupby -f severity --json --output severity_stats.json

# Daily data snapshots
DATE=$(date +%Y-%m-%d)
vulnsh search cve_created_at:$DATE --json --output "vulns_$DATE.json"
```

## Integration Patterns

### CI/CD Pipeline Integration

```bash
# Vulnerability scanning in pipelines
vulnsh search affected_products.product:docker --json --silent | \
  jq '.count' | xargs -I {} echo "Found {} Docker vulnerabilities"

# Baseline security checks
vulnsh search "(apache OR nginx)" severity:critical --count-only
```

### Security Monitoring Integration

```bash
# SIEM data enrichment
vulnsh id CVE-2021-44228 --json --silent | \
  jq '{cve_id, severity, cvss_score, is_kev, is_poc}'

# Threat intelligence feeds
vulnsh search is_kev:true age_in_days:30 --json --silent | \
  jq '.vulnerabilities[] | {cve_id, epss_score, cve_created_at}'
```

### Notification Workflows

```bash
# Slack notifications for critical vulnerabilities
CRITICALS=$(vulnsh search severity:critical age_in_days:1 --json --silent)
if [ "$(echo $CRITICALS | jq '.count')" -gt 0 ]; then
  echo $CRITICALS | jq -r '"New critical vulnerabilities: " + (.count | tostring)'
fi
```

## Query Optimization Tips

### Effective Field Usage

```bash
# Target specific vendors/products
vulnsh search affected_products.vendor:microsoft
vulnsh search affected_products.product:windows

# Combine multiple criteria efficiently
vulnsh search severity:critical is_remote:true is_poc:true

# Use ranges for scores
vulnsh search cvss_score:[8.0 TO 10.0]  # More efficient than cvss_score:>8.0
```

### Faceting for Analysis

```bash
# Understand data distribution before detailed searches
vulnsh search apache --term-facets severity=10,tags=5

# Multi-dimensional analysis
vulnsh search --term-facets severity=5,affected_products.vendor=10 \
  --range-facets numeric:cvss_score:high:8:10

# Time-based faceting
vulnsh search --range-facets date:cve_created_at:2024:2024-01:2024-12
```

## Common Patterns & Use Cases

### Security Research

```bash
# Find vulnerability families
vulnsh search "buffer overflow" severity:high
vulnsh search description:"SQL injection" --limit 100

# Exploitation research
vulnsh search is_poc:true cvss_score:>9.0 --sort-desc epss_score
vulnsh search tags:rce is_template:true
```

### Compliance & Reporting

```bash
# Generate compliance reports
vulnsh search affected_products.vendor:microsoft cve_created_at:2024 \
  --output microsoft_2024_vulns.json

# Risk assessment data
vulnsh groupby -f severity -q "is_remote:true"
vulnsh search severity:critical --fields cve_id,cvss_score,epss_score
```

### Incident Response

```bash
# Check if vulnerability is known exploited
vulnsh id CVE-2021-44228 --json | jq '.is_kev'

# Find related vulnerabilities
vulnsh search affected_products.vendor:apache "log4j"
vulnsh search tags:log4j --sort-desc cvss_score

# Impact assessment
vulnsh search affected_products.product:log4j is_remote:true
```

## Troubleshooting Advanced Usage

### Performance Issues

```bash
# Debug slow queries
vulnsh --debug search complex_query_here

# Check network connectivity
vulnsh healthcheck --verbose

# Optimize large result sets
vulnsh search broad_query --fields cve_id --limit 10  # Test first
```

### Data Quality

```bash
# Verify field names and values
vulnsh search help  # See available fields (requires API key)

# Test query syntax
vulnsh search 'test:value' --limit 1  # Verify syntax works

# Validate data ranges
vulnsh search cvss_score:[0 TO 10] --limit 1  # Check valid ranges
```

### API Limits & Rate Limiting

```bash
# Implement delays in scripts
vulnsh search query1 && sleep 1 && vulnsh search query2

# Use batch operations efficiently
vulnsh search large_query --limit 1000 --output batch1.json
```

## Best Practices Summary

### Query Construction
- **Start broad, filter progressively** - Begin with general terms, add constraints
- **Use specific fields** - `affected_products.vendor:apache` vs. generic `apache`
- **Combine filters logically** - `severity:critical AND is_remote:true`
- **Leverage ranges** - `cvss_score:[8 TO 10]` for score ranges

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

Remember: Start simple, iterate, and build complexity as needed. Use `vulnsh healthcheck` to verify connectivity, and always test queries with small limits before running large searches.