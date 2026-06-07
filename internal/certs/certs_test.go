package certs

import (
	"crypto/x509/pkix"
	"math/big"
	"testing"
	
	internalcrypto "micropki/internal/crypto"
)

func TestGenerateRootCertificate(t *testing.T) {
	key, err := internalcrypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("Failed to gen key: %v", err)
	}

	subject := &pkix.Name{CommonName: "Test Root"}
	serial := big.NewInt(1234)
	
	certPEM, err := GenerateRootCertificate(subject, &key.PublicKey, key, 365, serial)
	if err != nil {
		t.Fatalf("Failed to generate root cert: %v", err)
	}
	if len(certPEM) == 0 {
		t.Errorf("Expected cert PEM output, got empty")
	}
}
