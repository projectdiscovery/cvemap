package search

import "testing"

func TestValidateResultWindow(t *testing.T) {
	tests := []struct {
		name          string
		offset, limit int
		wantErr       bool
	}{
		{"within window", 9990, 10, false},
		{"server default limit", 9999, 0, false},
		{"over window", 9991, 10, true},
		{"offset at window", 10000, 0, true},
		{"negative offset", -1, 5, true},
		{"negative limit", 0, -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateResultWindow(tt.offset, tt.limit); (err != nil) != tt.wantErr {
				t.Errorf("ValidateResultWindow(%d, %d) error = %v, wantErr %v", tt.offset, tt.limit, err, tt.wantErr)
			}
		})
	}
}
