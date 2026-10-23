package clis

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestUnknownSearchFields(t *testing.T) {
	known := []string{"affected_products.vendor", "affected_products.product", "cvss_metrics", "cvss_score", "is_kev", "name", "severity", "cve_id", "tags"}
	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{"empty", "", nil},
		{"bare term", "log4j", nil},
		{"known field", "is_kev:true", nil},
		{"unknown field", "nonexistent_field:foo", []string{"nonexistent_field"}},
		{"nested known", "affected_products.vendor:apache", nil},
		{"nested parent", "affected_products:apache", nil},
		{"child of known object", "cvss_metrics.cvss31.score:>9", nil},
		{"nested unknown", "affected_products.version:1.0", []string{"affected_products.version"}},
		{"range", "cvss_score:>=9 && severity:critical", nil},
		{"range brackets", "cvss_score:[7 TO 9] && foo:bar", []string{"foo"}},
		{"quoted value with colon", `name:"a:b" && is_kev:true`, nil},
		{"single quoted value", `name:'x:y z:w'`, nil},
		{"escaped quote", `name:"a\"b:c" && is_kev:true`, nil},
		{"quoted cpe", `vulnerable_cpe:"cpe:2.3:a:adobe:acrobat_reader_dc:*"`, []string{"vulnerable_cpe"}},
		{"unquoted cpe", `vulnerable_cpe:cpe:2.3:a:adobe:reader`, []string{"vulnerable_cpe"}},
		{"cpe phrase alone", `"cpe:2.3:a:adobe:reader"`, nil},
		{"booleans", "is_kev:true || foo:1 && !bar:2", []string{"foo", "bar"}},
		{"no spaces", "is_kev:true&&foo:1||bar:2", []string{"foo", "bar"}},
		{"not keyword", "NOT foo:1 AND is_kev:false", []string{"foo"}},
		{"negation prefix", "-foo:1 +is_kev:true", []string{"foo"}},
		{"parentheses", "((foo:1 || is_kev:true) && (bar:2))", []string{"foo", "bar"}},
		{"duplicates", "foo:1 || foo:2", []string{"foo"}},
		{"flag built wrapper", "(foo:1) && (affected_products.product:x || affected_products.vendor:x)", []string{"foo"}},
		{"url value", "tags:http://example.com:8080/a", nil},
		{"mid word colon", "abc-def:1", nil},
		{"unlisted description", "description:foo", nil},
		{"unlisted created_at range", "created_at:>2024", nil},
		{"unlisted cpe", `affected_products.cpe:"cpe:2.3:a:x:y"`, nil},
		{"unlisted exposure values", "exposure.values.country:US", nil},
		{"plus prefix unknown", "+vulnerable_cpe:x", []string{"vulnerable_cpe"}},
		{"equals separator unknown", "vulnerable_cpe=x", []string{"vulnerable_cpe"}},
		{"equals separator known", "is_kev=true && severity=critical", nil},
		{"equals inside value", "tags:a=b", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unknownSearchFields(tt.query, known); !slices.Equal(got, tt.want) {
				t.Errorf("unknownSearchFields(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

func TestLogUnknownSearchFieldWritesStderr(t *testing.T) {
	var buf bytes.Buffer
	orig := unknownFieldWriter
	t.Cleanup(func() { unknownFieldWriter = orig })
	unknownFieldWriter = &buf

	logUnknownSearchField("vulnerable_cpe")

	got := buf.String()
	if !strings.Contains(got, `not a known search field`) || !strings.Contains(got, "vulnerable_cpe") {
		t.Errorf("stderr warning = %q, want unknown-field hint", got)
	}
}
