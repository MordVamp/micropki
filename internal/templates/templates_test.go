package templates

import (
	"crypto/x509/pkix"
	"math/big"
	"testing"
)

func TestTemplates_String(t *testing.T) {
	if Server.String() != "server" {
		t.Errorf("expected server, got %s", Server.String())
	}
	if Client.String() != "client" {
		t.Errorf("expected client, got %s", Client.String())
	}
	if CodeSigning.String() != "code_signing" {
		t.Errorf("expected code_signing, got %s", CodeSigning.String())
	}
	unknown := TemplateType(99)
	if unknown.String() != "unknown" {
		t.Errorf("expected unknown, got %s", unknown.String())
	}
}

func TestParseTemplate(t *testing.T) {
	tests := []struct {
		input    string
		expected TemplateType
		hasErr   bool
	}{
		{"server", Server, false},
		{"client", Client, false},
		{"code_signing", CodeSigning, false},
		{"invalid", 0, true},
	}

	for _, tc := range tests {
		tt, err := ParseTemplate(tc.input)
		if tc.hasErr {
			if err == nil {
				t.Errorf("expected error for %s", tc.input)
			}
		} else {
			if err != nil || tt != tc.expected {
				t.Errorf("expected %v, got %v (err: %v)", tc.expected, tt, err)
			}
		}
	}
}

func TestBuildTemplate(t *testing.T) {
	subj := &pkix.Name{CommonName: "Test"}
	serial := big.NewInt(123)

	// Server template success
	tmpl, err := BuildTemplate(Server, subj, []string{"dns:example.com"}, 365, serial)
	if err != nil || tmpl == nil {
		t.Errorf("expected success, got err: %v", err)
	}

	// Server template failure (no SAN)
	_, err = BuildTemplate(Server, subj, []string{}, 365, serial)
	if err == nil {
		t.Errorf("expected err for server without SANs")
	}

	// Client template success
	tmpl, err = BuildTemplate(Client, subj, []string{"email:test@example.com"}, 365, serial)
	if err != nil || tmpl == nil {
		t.Errorf("expected success, got err: %v", err)
	}

	// CodeSigning failure (IP SAN)
	_, err = BuildTemplate(CodeSigning, subj, []string{"ip:1.1.1.1"}, 365, serial)
	if err == nil {
		t.Errorf("expected err for code_signing with IP SAN")
	}

	// CodeSigning success
	tmpl, err = BuildTemplate(CodeSigning, subj, []string{"uri:http://example.com"}, 365, serial)
	if err != nil || tmpl == nil {
		t.Errorf("expected success, got err: %v", err)
	}
}

func TestParseSANs_Errors(t *testing.T) {
	tests := []struct {
		input  string
		hasErr bool
	}{
		{"invalid-format", true},
		{"unknown:value", true},
		{"ip:not-an-ip", true},
		{"email:not-an-email", true},
		{"uri::invalid", true},
	}

	for _, tc := range tests {
		_, _, _, _, err := parseSANs([]string{tc.input})
		if (err != nil) != tc.hasErr {
			t.Errorf("expected err=%v for %s, got %v", tc.hasErr, tc.input, err)
		}
	}
}
