package client

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenCSR(t *testing.T) {
	outKey := filepath.Join(t.TempDir(), "test.key")
	outCsr := filepath.Join(t.TempDir(), "test.csr")

	cmd := genCsrCmd
	// Override the standard args for test encapsulation
	cmd.SetArgs([]string{
		"--subject", "CN=micropki.test.com",
		"--key-type", "rsa",
		"--key-size", "2048",
		"--out-key", outKey,
		"--out-csr", outCsr,
	})
	
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Gen-CSR CLI command execution failed natively: %v", err)
	}

	csrBytes, err := os.ReadFile(outCsr)
	if err != nil {
		t.Fatalf("Failed to retrieve generated CSR file payload: %v", err)
	}

	block, _ := pem.Decode(csrBytes)
	if block == nil {
		t.Fatal("Failed to decode CSR standard PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Failed parsing raw bytes back to x509 CSR objects via crypto: %v", err)
	}

	if csr.Subject.CommonName != "micropki.test.com" {
		t.Errorf("Expected Subject dynamically binding to 'micropki.test.com', instead got %s", csr.Subject.CommonName)
	}
	
	// Ensure the private key signed perfectly mapping public structures across boundaries
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("Mathematically invalid signature on resulting CSR detected natively: %v", err)
	}
}
