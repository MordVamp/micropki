package ocsp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"micropki/internal/certs"
	internalcrypto "micropki/internal/crypto"
)

func TestNewResponder(t *testing.T) {
	dir := t.TempDir()

	caKey, _ := internalcrypto.GenerateRSAKey(2048)
	caSubject := &pkix.Name{CommonName: "Test CA"}
	caCertPEM, _ := certs.GenerateRootCertificate(caSubject, &caKey.PublicKey, caKey, 365, big.NewInt(1))
	caCertPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(caCertPath, caCertPEM, 0644)

	ocspKey, _ := internalcrypto.GenerateRSAKey(2048)
	ocspSubject := &pkix.Name{CommonName: "OCSP"}
	ocspCertPEM, _ := certs.GenerateRootCertificate(ocspSubject, &ocspKey.PublicKey, ocspKey, 365, big.NewInt(2))
	ocspCertPath := filepath.Join(dir, "ocsp.pem")
	os.WriteFile(ocspCertPath, ocspCertPEM, 0644)

	keyBytes, _ := x509.MarshalPKCS8PrivateKey(ocspKey)
	ocspKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	ocspKeyPath := filepath.Join(dir, "ocsp.key")
	os.WriteFile(ocspKeyPath, ocspKeyPEM, 0600)

	responder, err := NewResponder(ocspCertPath, ocspKeyPath, caCertPath)
	if err != nil {
		t.Fatalf("NewResponder failed: %v", err)
	}
	if responder == nil {
		t.Fatalf("Expected responder")
	}
}
