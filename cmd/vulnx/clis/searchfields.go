package clis

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/projectdiscovery/vulnx/v2/pkg/tools/filters"
)

// unknownFieldWriter is stderr so the hint still shows with --silent.
// gologger Info/Warning are dropped at LevelSilent, and Silent() writes stdout.
var unknownFieldWriter io.Writer = os.Stderr

// warnUnknownSearchFields hints at typos or outdated field names when a query
// matched nothing, since the API silently matches no documents for them.
func warnUnknownSearchFields(query string) {
	if query == "" {
		return
	}
	defs, err := filters.NewHandler(vulnxClient).List()
	if err != nil {
		return
	}
	known := make([]string, len(defs))
	for i, def := range defs {
		known[i] = def.Field
	}
	for _, field := range unknownSearchFields(query, known) {
		logUnknownSearchField(field)
	}
}

func logUnknownSearchField(field string) {
	_, _ = fmt.Fprintf(unknownFieldWriter, "[WRN] %q is not a known search field, run 'vulnx filters' to list available fields\n", field)
}

// The filters endpoint is hand-curated and omits some indexed fields that
// queries still accept.
var unlistedSearchFields = []string{
	"created_at",
	"description",
	"affected_products.cpe",
	"affected_products.summary",
	"affected_products.projects",
	"exposure.values",
}

// unknownSearchFields returns the fields used in query that are not in known,
// in order of first appearance and without duplicates.
func unknownSearchFields(query string, known []string) []string {
	var unknown []string
	for _, field := range queryFields(query) {
		if !isKnownSearchField(field, known) && !slices.Contains(unknown, field) {
			unknown = append(unknown, field)
		}
	}
	return unknown
}

// isKnownSearchField also accepts parents and children of known fields
// (e.g. "affected_products" or "cvss_metrics.cvss31") so the hint never
// flags a field the API might still understand.
func isKnownSearchField(field string, known []string) bool {
	matches := func(k string) bool {
		return k == field || strings.HasPrefix(k, field+".") || strings.HasPrefix(field, k+".")
	}
	return slices.ContainsFunc(known, matches) || slices.ContainsFunc(unlistedSearchFields, matches)
}

// queryFields extracts field names from a query conservatively: only
// identifiers at a term boundary followed by ':' or '=' outside quoted strings, and
// never anything inside a field's value (e.g. unquoted CPE strings).
func queryFields(query string) []string {
	var fields []string
	for i := 0; i < len(query); {
		c := query[i]
		switch {
		case c == '"' || c == '\'':
			i = skipQuoted(query, i)
		case isFieldStart(c) && atTermBoundary(query, i):
			j := i
			for j < len(query) && isFieldChar(query[j]) {
				j++
			}
			if j < len(query) && (query[j] == ':' || query[j] == '=') {
				fields = append(fields, strings.TrimRight(query[i:j], "."))
				i = skipValue(query, j+1)
			} else {
				i = j
			}
		default:
			i++
		}
	}
	return fields
}

func skipQuoted(s string, i int) int {
	quote := s[i]
	for i++; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == quote {
			return i + 1
		}
	}
	return len(s)
}

func skipValue(s string, i int) int {
	if i < len(s) && (s[i] == '[' || s[i] == '{') {
		if end := strings.IndexAny(s[i:], "]}"); end >= 0 {
			return i + end + 1
		}
		return len(s)
	}
	for i < len(s) && !strings.ContainsRune(" \t\r\n()", rune(s[i])) {
		if s[i] == '"' || s[i] == '\'' {
			return skipQuoted(s, i)
		}
		if strings.HasPrefix(s[i:], "&&") || strings.HasPrefix(s[i:], "||") {
			return i
		}
		i++
	}
	return i
}

func atTermBoundary(s string, i int) bool {
	isBoundary := func(k int) bool {
		return k < 0 || strings.ContainsRune(" \t\r\n(!&|", rune(s[k]))
	}
	if isBoundary(i - 1) {
		return true
	}
	return (s[i-1] == '-' || s[i-1] == '+') && isBoundary(i-2)
}

func isFieldStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isFieldChar(c byte) bool {
	return isFieldStart(c) || c == '.' || (c >= '0' && c <= '9')
}
