package clis

import (
	"slices"
	"testing"
)

func TestMergeFields(t *testing.T) {
	base := []string{"doc_id", "cve_id"}
	got := mergeFields(base, []string{"doc_id", "severity"})
	if want := []string{"doc_id", "cve_id", "severity"}; !slices.Equal(got, want) {
		t.Errorf("mergeFields = %v, want %v", got, want)
	}
	if len(base) != 2 {
		t.Errorf("mergeFields mutated base: %v", base)
	}
}

func TestValidateSearchInputsResultWindow(t *testing.T) {
	origLimit, origOffset, origFacetSize := searchLimit, searchOffset, searchFacetSize
	t.Cleanup(func() { searchLimit, searchOffset, searchFacetSize = origLimit, origOffset, origFacetSize })
	searchFacetSize = 10

	tests := []struct {
		name    string
		offset  int
		limit   int
		wantErr bool
	}{
		{"defaults", 0, 10, false},
		{"last page", 9990, 10, false},
		{"full window", 0, 10000, false},
		{"server default limit", 9999, 0, false},
		{"offset at window", 10000, 10, true},
		{"offset at window with default limit", 10000, 0, true},
		{"sum over window", 9000, 10000, true},
		{"one past window", 9991, 10, true},
		{"limit over max", 0, 10001, true},
		{"negative offset", -1, 10, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			searchOffset, searchLimit = tt.offset, tt.limit
			if err := validateSearchInputs(); (err != nil) != tt.wantErr {
				t.Errorf("validateSearchInputs(offset=%d, limit=%d) error = %v, wantErr %v", tt.offset, tt.limit, err, tt.wantErr)
			}
		})
	}
}
