package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"testing"
)

func TestValidateKey(t *testing.T) {
	privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)

	if err := ValidateKey(&privRSA.PublicKey, "root"); err == nil {
		t.Errorf("Expected error for 2048-bit RSA root key")
	}
	if err := ValidateKey(&privRSA.PublicKey, "end-entity"); err != nil {
		t.Errorf("Did not expect error for 2048-bit RSA end-entity key: %v", err)
	}

	privECC, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := ValidateKey(&privECC.PublicKey, "intermediate"); err == nil {
		t.Errorf("Expected error for P-256 ECC CA key")
	}
	privECC2, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err := ValidateKey(&privECC2.PublicKey, "end-entity"); err == nil {
		t.Errorf("Expected error for P-224 ECC end-entity key")
	}

	// Unsupported key type
	if err := ValidateKey("not-a-public-key", "end-entity"); err == nil {
		t.Errorf("Expected error for unsupported key type")
	}
}

func TestValidateValidity(t *testing.T) {
	if err := ValidateValidity(4000, "root"); err == nil {
		t.Errorf("Expected error for 4000 days root validity")
	}
	if err := ValidateValidity(2000, "intermediate"); err == nil {
		t.Errorf("Expected error for 2000 days intermediate validity")
	}
	if err := ValidateValidity(1000, "end-entity"); err == nil {
		t.Errorf("Expected error for 1000 days end-entity validity")
	}
	if err := ValidateValidity(100, "end-entity"); err != nil {
		t.Errorf("Unexpected error for 100 days end-entity validity: %v", err)
	}
}

func TestValidateSANs(t *testing.T) {
	dnsNames := []string{"*.example.com"}
	if err := ValidateSANs(dnsNames, nil, nil, nil, "server"); err == nil {
		t.Errorf("Expected error for wildcard SAN")
	}

	validDNS := []string{"example.com"}
	ips := []net.IP{net.ParseIP("192.168.1.1")}
	if err := ValidateSANs(validDNS, nil, ips, nil, "server"); err != nil {
		t.Errorf("Unexpected error for valid server SANs: %v", err)
	}

	// Server template prohibits email and URI
	if err := ValidateSANs(nil, []string{"test@example.com"}, nil, nil, "server"); err == nil {
		t.Errorf("Expected error for server template with email SAN")
	}

	// Client template prohibits IP and URI
	if err := ValidateSANs(nil, nil, ips, nil, "client"); err == nil {
		t.Errorf("Expected error for client template with IP SAN")
	}

	// Code signing template prohibits IP and email
	if err := ValidateSANs(nil, []string{"test@example.com"}, nil, nil, "code_signing"); err == nil {
		t.Errorf("Expected error for code_signing template with email SAN")
	}
}
