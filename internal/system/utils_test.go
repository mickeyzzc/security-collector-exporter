package system

import "testing"

func TestBoolToFloat64(t *testing.T) {
	tests := []struct {
		input    bool
		expected float64
	}{
		{true, 1.0},
		{false, 0.0},
	}
	for _, tc := range tests {
		got := BoolToFloat64(tc.input)
		if got != tc.expected {
			t.Errorf("BoolToFloat64(%v) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}
