package crl

import (
	"testing"
)

func TestReasonCodeMapping(t *testing.T) {
	tests := []struct {
		reason string
		want   int
	}{
		{"unspecified", 0},
		{"keycompromise", 1},
		{"cacompromise", 2},
		{"affiliationchanged", 3},
		{"superseded", 4},
		{"cessationofoperation", 5},
		{"certificatehold", 6},
		{"removefromcrl", 8},
		{"privilegewithdrawn", 9},
		{"aacompromise", 10},
		{"invalidreason", 0}, // Default missing maps to 0
	}

	for _, tc := range tests {
		got, exists := ReasonCodeMap[tc.reason]
		if !exists && tc.reason != "invalidreason" {
			t.Errorf("Missing expected reason code mapping for %s", tc.reason)
		}
		if exists && got != tc.want {
			t.Errorf("ReasonCodeMap[%s] = %d; want %d", tc.reason, got, tc.want)
		}
	}
}
