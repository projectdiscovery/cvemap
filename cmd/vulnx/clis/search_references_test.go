package clis

import (
	"strings"
	"testing"
)

// Issue #81: default search layout must expose citation links.
func TestDefaultLayoutIncludesReferences(t *testing.T) {
	if !strings.Contains(defaultLayoutJSON, "{references}") {
		t.Errorf("default layout should include {references} placeholder (issue #81)")
	}
	if !strings.Contains(defaultLayoutJSON, "citations.length == 0") {
		t.Errorf("default layout references line should omit when citations are empty")
	}
}
