# Vulnerability CLI Renderer

This package provides a flexible CLI renderer for vulnerability search results that uses a JSON-based layout configuration system.

## Features

- **Flexible Layout Configuration**: Define output format using JSON configuration
- **Smart Omission Rules**: Automatically hide empty or irrelevant fields
- **List Truncation**: Show first N items with "+X more" indicator
- **Formatted Output**: Pretty-print numbers, booleans, and exposure counts
- **Exploit Detection**: Automatically detect if a vulnerability has been exploited

## Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/projectdiscovery/vulnx/pkg/tools/renderer"
    "github.com/projectdiscovery/vulnx"
)

func main() {
    // Define layout configuration
    layoutJSON := `[
        {
            "line": 1,
            "format": "[{doc_id}] {severity} - {title}",
            "omit_if": []
        },
        {
            "line": 2,
            "format": "↳ Authors: {authors} | Vuln Age: {age_in_days}d | EPSS: {epss_score} | CVSS: {cvss_score}",
            "omit_if": ["authors.length == 0", "epss_score == 0", "cvss_score == 0"]
        }
    ]`

    // Parse layout
    layout, err := renderer.ParseLayout([]byte(layoutJSON))
    if err != nil {
        log.Fatal(err)
    }

    // Convert vulnerability to entry
    entry := renderer.FromVulnerability(vuln)
    entries := []*renderer.Entry{entry}

    // Render output
    result := renderer.Render(entries, layout, 1, 1)
    fmt.Println(result)
}
```

## Layout Configuration

The layout is defined as a JSON array of `LayoutLine` objects:

```json
[
  {
    "line": 1,
    "format": "[{doc_id}] {severity} - {title}",
    "omit_if": []
  },
  {
    "line": 2,
    "format": "↳ Authors: {authors} | Vuln Age: {age_in_days}d",
    "omit_if": ["authors.length == 0"]
  }
]
```

### Available Placeholders

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{doc_id}` | Document ID | `CVE-2024-1234` |
| `{severity}` | Severity level (capitalized) | `Critical` |
| `{title}` | Vulnerability title | `Remote Code Execution` |
| `{authors}` | Authors (max 3, then "+N") | `author1, author2, author3 +2` |
| `{age_in_days}` | Age in days | `123` |
| `{age_urgency}` | Age with urgency indicators | `5d (NEW)`, `25d (RECENT)`, `90d` |
| `{epss_score}` | EPSS score | `0.85` |
| `{cvss_score}` | CVSS score | `9.1` |
| `{exposure}` | Exposure count | `~15.0K` or `unknown` |
| `{vendors}` | Distinct vendors (max 3) | `vendor1, vendor2 +1` |
| `{products}` | Distinct products (max 3) | `product1, product2 +1` |
| `{patch}` | Patch availability | `✔` or `✘` |
| `{poc_count}` | POC count | `3` or `✘` |
| `{kev}` | KEV status | `✔` or `✘` |
| `{template}` | Template availability | `✔` or `✘` |
| `{exploit_seen}` | Exploit detected | `✔` or `✘` |
| `{hackerone}` | HackerOne reports | `✔` or `✘` |
| `{tags}` | Tags (max 3) | `rce, auth-bypass +1` |

### Omission Rules

The `omit_if` array contains conditions that will cause a line to be omitted:

- `"authors.length == 0"` - Omit if no authors
- `"epss_score == 0"` - Omit if EPSS score is 0
- `"cvss_score == 0"` - Omit if CVSS score is 0
- `"exposure == 0"` - Omit if exposure is 0 or unknown
- `"vendors.length == 0"` - Omit if no vendors
- `"products.length == 0"` - Omit if no products
- `"tags.length == 0"` - Omit if no tags

## Formatting Rules

### Exposure Formatting
- `0` → `"unknown"`
- `1-999` → as-is (e.g., `"500"`)
- `1000+` → `"~12.3K"` format

### Boolean Formatting
- `true` → `"✔"`
- `false` → `"✘"`

### POC Count Formatting
- `0` → `"✘"`
- `>0` → numeric value (e.g., `"3"`)

### List Truncation
- Shows up to 3 items
- Additional items shown as `" +N"`
- Example: `"item1, item2, item3 +2"`

### Age Urgency Indicators
- `≤7 days` → `"5d (NEW)"` - Shows NEW indicator for recently disclosed vulnerabilities
- `≤30 days` → `"25d (RECENT)"` - Shows RECENT indicator for recently disclosed vulnerabilities
- `>30 days` → `"90d"` - Shows age only for older vulnerabilities

## Exploit Detection

The renderer automatically detects if a vulnerability has been exploited based on:

1. **POC sources** containing exploit keywords: `exploit`, `exploiting`, `exploitation`, `exploitable`
2. **Citation URLs** from exploit domains: `exploit-db.com`, `exploitdb.com`, `metasploit.com`
3. **Description/Impact** containing phrases:
   - "exploited in the wild"
   - "actively exploited"
   - "used in attacks"
   - "real-world exploitation"

## Color Highlighting

The renderer includes intelligent color highlighting for better readability:

### Severity Colors
- **Critical** - Bright red for maximum urgency
- **High** - Red for high importance
- **Medium** - Yellow for moderate attention
- **Low** - Green for low priority

### Age Urgency Colors
- **(NEW)** - Bright cyan for freshly disclosed vulnerabilities ≤7 days old
- **(RECENT)** - Bright blue for recently disclosed vulnerabilities ≤30 days old

### Priority & Status Colors
- **IMMEDIATE/URGENT** - Red for critical priorities
- **HIGH/MEDIUM** - Yellow for important priorities
- **LOW** - Green for low priority
- **EXPLOITS AVAILABLE** - Bright yellow for exploit availability
- **KEV LISTED** - Bright magenta for KEV status
- **✔/✘** - Green/Red for boolean indicators

### Color Control
- Colors are automatically enabled for terminal output
- Colors are disabled for non-terminal output (pipes, files)
- Use `--no-color` flag to disable colors manually

## Example Output

```
[CVE-2024-1234] Critical - Remote Code Execution Vulnerability
↳ Authors: security-team, researcher | Vuln Age: 30d | EPSS: 0.85 | CVSS: 9.1
↳ Exposure: ~15.0K | Vendors: example-corp | Products: webapp, api-server
↳ Patch: ✔ | POCs: 2 | KEV: ✔ | Template: ✘ | Exploit Seen: ✔ | HackerOne: ✔
↳ Tags: rce, auth-bypass
↳ Showing 1 of 1 total results
```

## API Reference

### Types

```go
type LayoutLine struct {
    Line   int      `json:"line"`
    Format string   `json:"format"`
    OmitIf []string `json:"omit_if"`
}

type Entry struct {
    DocID              string
    Name               string
    Severity           string
    Author             []string
    AgeInDays          int
    EpssScore          float64
    CvssScore          float64
    Exposure           *vulnx.VulnExposure
    AffectedProducts   []*vulnx.ProductInfo
    IsPatchAvailable   bool
    PocCount           int
    IsKev              bool
    IsTemplate         bool
    H1                 *vulnx.H1Stats
    Tags               []string
    Pocs               []*vulnx.POC
    Citations          []*vulnx.Citation
    Description        string
    Impact             string
}
```

### Functions

```go
// ParseLayout parses layout JSON into LayoutLine structs
func ParseLayout(layoutJSON []byte) ([]LayoutLine, error)

// FromVulnerability converts a vulnx.Vulnerability to an Entry
func FromVulnerability(v *vulnx.Vulnerability) *Entry

// Render generates formatted output for vulnerability entries
func Render(entries []*Entry, layout []LayoutLine, totalResults, shownResults int) string
```

## Testing

Run the test suite:

```bash
go test ./pkg/tools/renderer/...
```

The package includes comprehensive tests covering:
- Layout parsing
- Placeholder replacement
- Omission rules
- Formatting functions
- Exploit detection
- List truncation
- Expected output validation
