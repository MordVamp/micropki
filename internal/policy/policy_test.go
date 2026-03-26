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
}

func TestValidateValidity(t *testing.T) {
	if err := ValidateValidity(4000, "root"); err == nil {
		t.Errorf("Expected error for 4000 days root validity")
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
}
