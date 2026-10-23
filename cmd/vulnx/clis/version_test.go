package clis

import "testing"

func TestShouldSuggestUpdate(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{current: "v2.0.2", latest: "2.0.2", want: false},
		{current: "v2.0.2", latest: "v2.0.2", want: false},
		{current: "2.0.2", latest: "v2.0.2", want: false},
		{current: "v2.0.2", latest: "2.0.3", want: true},
		{current: "v2.0.3", latest: "2.0.2", want: false},
	}
	for _, tt := range tests {
		got := shouldSuggestUpdate(tt.current, tt.latest)
		if got != tt.want {
			t.Errorf("shouldSuggestUpdate(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}
