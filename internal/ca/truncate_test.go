package ca

import "testing"

func TestTruncateString(t *testing.T) {
	if TruncateString("hello world", 5) != "he..." {
		t.Errorf("expected he..., got %s", TruncateString("hello world", 5))
	}
	if TruncateString("hi", 5) != "hi" {
		t.Errorf("expected hi, got %s", TruncateString("hi", 5))
	}
}
