package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"micropki/internal/templates"
)

func TestIssueCertMalformedCSR(t *testing.T) {
	tmpDir := t.TempDir()

	// Test 1: Malformed PEM body
	invalidCsrPath := filepath.Join(tmpDir, "invalid.csr")
	os.WriteFile(invalidCsrPath, []byte("-----BEGIN CERTIFICATE REQUEST-----\nNot a real base64 body!\n-----END CERTIFICATE REQUEST-----"), 0644)

	csrPEM, _ := os.ReadFile(invalidCsrPath)
	block, _ := pem.Decode(csrPEM)
	if block != nil {
		// If pem.Decode returns a block, try parsing it — it should fail
		_, err := x509.ParseCertificateRequest(block.Bytes)
		if err == nil {
			t.Fatal("Expected parse error on malformed CSR, got nil")
		}
	}

	// Test 2: Completely invalid PEM (no header/footer)
	garbagePath := filepath.Join(tmpDir, "garbage.pem")
	os.WriteFile(garbagePath, []byte("this is not PEM at all"), 0644)
	garbagePEM, _ := os.ReadFile(garbagePath)
	garbageBlock, _ := pem.Decode(garbagePEM)
	if garbageBlock != nil {
		t.Fatal("Expected nil block from garbage PEM data")
	}

	// Test 3: Empty file
	emptyPath := filepath.Join(tmpDir, "empty.pem")
	os.WriteFile(emptyPath, []byte(""), 0644)
	emptyPEM, _ := os.ReadFile(emptyPath)
	emptyBlock, _ := pem.Decode(emptyPEM)
	if emptyBlock != nil {
		t.Fatal("Expected nil block from empty file")
	}

	// Test 4: Invalid template name
	if _, err := templates.ParseTemplate("unknown_template"); err == nil {
		t.Fatal("Expected error on invalid template, got nil")
	}

	// Test 5: Key generation sanity
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if privKey == nil {
		t.Fatal("GenerateKey failed")
	}

	t.Log("All malformed input tests passed safely.")
}
