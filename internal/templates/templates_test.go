package templates

import (
	"crypto/x509/pkix"
	"math/big"
	"testing"
)

func TestTemplates(t *testing.T) {
	tmplServer, err := ParseTemplate("server")
	if err != nil || tmplServer != Server {
		t.Errorf("Failed to parse server template")
	}

	tmplClient, err := ParseTemplate("client")
	if err != nil || tmplClient != Client {
		t.Errorf("Failed to parse client template")
	}

	tmplCodeSigning, err := ParseTemplate("code_signing")
	if err != nil || tmplCodeSigning != CodeSigning {
		t.Errorf("Failed to parse code_signing template")
	}

	_, err = ParseTemplate("unknown")
	if err == nil {
		t.Errorf("Expected error for unknown template")
	}

	subject := &pkix.Name{CommonName: "test"}
	serial := big.NewInt(1)

	// Server template success
	sans := []string{"dns:example.com", "ip:1.1.1.1"}
	certTmpl, err := BuildTemplate(Server, subject, sans, 365, serial)
	if err != nil {
		t.Errorf("BuildTemplate (server) failed: %v", err)
	}
	if len(certTmpl.DNSNames) != 1 || len(certTmpl.IPAddresses) != 1 {
		t.Errorf("Expected 1 DNS and 1 IP SAN")
	}

	// Server template missing SAN
	_, err = BuildTemplate(Server, subject, []string{}, 365, serial)
	if err == nil {
		t.Errorf("Expected error for server without SAN")
	}

	// CodeSigning template with IP SAN
	_, err = BuildTemplate(CodeSigning, subject, []string{"ip:1.1.1.1"}, 365, serial)
	if err == nil {
		t.Errorf("Expected error for code_signing with IP SAN")
	}

	// Invalid SAN
	_, err = BuildTemplate(Client, subject, []string{"invalid"}, 365, serial)
	if err == nil {
		t.Errorf("Expected error for invalid SAN format")
	}

	_, err = BuildTemplate(Client, subject, []string{"ip:invalid"}, 365, serial)
	if err == nil {
		t.Errorf("Expected error for invalid IP SAN format")
	}

	_, err = BuildTemplate(Client, subject, []string{"email:invalid"}, 365, serial)
	if err == nil {
		t.Errorf("Expected error for invalid email SAN format")
	}
}
