package ca

import "testing"

func TestParseDN(t *testing.T) {
	dnStr := "CN=Test Root CA,O=My Org,OU=IT,C=US,ST=California,L=San Francisco"
	name, err := ParseDN(dnStr)
	if err != nil {
		t.Fatalf("ParseDN failed: %v", err)
	}
	if name.CommonName != "Test Root CA" {
		t.Errorf("expected CN=Test Root CA, got %v", name.CommonName)
	}
	if len(name.Organization) > 0 && name.Organization[0] != "My Org" {
		t.Errorf("expected O=My Org, got %v", name.Organization)
	}
	
	// Test invalid
	_, err = ParseDN("invalid_format")
	if err == nil {
		t.Error("expected error for invalid DN format")
	}
}
