package templates

import "testing"

func TestString(t *testing.T) {
	if Server.String() != "server" {
		t.Errorf("expected server")
	}
	if Client.String() != "client" {
		t.Errorf("expected client")
	}
	if CodeSigning.String() != "code_signing" {
		t.Errorf("expected code_signing")
	}
	// Test unknown
	var unknown TemplateType = 999
	if unknown.String() != "unknown" {
		t.Errorf("expected unknown")
	}
}
