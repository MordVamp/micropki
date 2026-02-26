package tests

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"micropki/internal/ca"
	"micropki/internal/certs"
	internalcrypto "micropki/internal/crypto"
	"micropki/internal/policy"
)

// TestParseDN verifies DN parsing.
func TestParseDN(t *testing.T) {
	tests := []struct {
		input    string
		expected string // String() representation of pkix.Name
		wantErr  bool
	}{
		{"CN=Test CA,O=Org,C=US", "CN=Test CA,O=Org,C=US", false},
		{"/CN=Test CA/O=Org/C=US", "CN=Test CA,O=Org,C=US", false},
		{"CN=Only", "CN=Only", false},
		{"invalid", "", true},
	}
	for _, tt := range tests {
		name, err := ca.ParseDN(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseDN(%q) expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDN(%q) unexpected error: %v", tt.input, err)
			continue
		}
		got := name.String()
		if got != tt.expected {
			t.Errorf("ParseDN(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// TestKeyGeneration tests RSA and ECC key generation.
func TestKeyGeneration(t *testing.T) {
	// RSA
	rsaKey, err := internalcrypto.GenerateRSAKey(4096)
	if err != nil {
		t.Fatalf("GenerateRSAKey failed: %v", err)
	}
	if rsaKey.N.BitLen() != 4096 {
		t.Errorf("RSA key size = %d, want 4096", rsaKey.N.BitLen())
	}

	// ECC
	eccKey, err := internalcrypto.GenerateECCKey()
	if err != nil {
		t.Fatalf("GenerateECCKey failed: %v", err)
	}
	if eccKey.Curve.Params().Name != "P-384" {
		t.Errorf("ECC curve = %s, want P-384", eccKey.Curve.Params().Name)
	}
}

// TestCertificateGeneration creates a self-signed cert and verifies it.
func TestCertificateGeneration(t *testing.T) {
	// Generate a test key (RSA)
	priv, err := internalcrypto.GenerateRSAKey(4096)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey

	name := pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"TestOrg"},
	}
	serial := big.NewInt(12345)
	validityDays := 365

	certPEM, err := certs.GenerateRootCertificate(&name, pub, priv, validityDays, serial)
	if err != nil {
		t.Fatalf("GenerateRootCertificate failed: %v", err)
	}

	// Parse the certificate back
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("Failed to decode PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	// Basic checks
	if !cert.IsCA {
		t.Error("Certificate is not marked as CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("Certificate missing keyCertSign usage")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("Certificate missing cRLSign usage")
	}
	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid false")
	}
	if len(cert.SubjectKeyId) == 0 {
		t.Error("SubjectKeyId missing")
	}
	if !bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
		t.Error("AKI not equal to SKI for self-signed")
	}
	if cert.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("Serial number = %v, want %v", cert.SerialNumber, serial)
	}
}

// TestEncryptedKeyRoundTrip generates a key, encrypts, then decrypts.
func TestEncryptedKeyRoundTrip(t *testing.T) {
	priv, err := internalcrypto.GenerateRSAKey(4096)
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("test-passphrase")

	encryptedPEM, err := internalcrypto.EncryptPrivateKey(priv, passphrase)
	if err != nil {
		t.Fatalf("EncryptPrivateKey failed: %v", err)
	}

	// Decrypt using x509.DecryptPEMBlock
	block, _ := pem.Decode(encryptedPEM)
	if block == nil {
		t.Fatal("Failed to decode encrypted PEM")
	}
	der, err := x509.DecryptPEMBlock(block, passphrase)
	if err != nil {
		t.Fatalf("DecryptPEMBlock failed: %v", err)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey failed: %v", err)
	}
	rsaParsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("Decrypted key is not RSA")
	}
	if rsaParsed.N.Cmp(priv.N) != 0 {
		t.Error("Decrypted key does not match original")
	}
}

// TestSKIComputation tests that SKI is computed correctly.
func TestSKIComputation(t *testing.T) {
	priv, err := internalcrypto.GenerateRSAKey(4096)
	if err != nil {
		t.Fatal(err)
	}
	ski, err := internalcrypto.ComputeSKI(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI failed: %v", err)
	}
	if len(ski) != 20 { // SHA-1 hash length
		t.Errorf("SKI length = %d, want 20", len(ski))
	}
}

// TestPolicyWrite tests that policy.txt is written correctly.
func TestPolicyWrite(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "policy-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	policyPath := filepath.Join(tmpDir, "policy.txt")
	name := pkix.Name{CommonName: "Test CA"}
	serial := big.NewInt(12345)
	validityDays := 365
	keyType := "rsa"
	keySize := 4096

	if err := policy.Write(policyPath, &name, serial, validityDays, keyType, keySize); err != nil {
		t.Fatalf("policy.Write failed: %v", err)
	}

	data, err := ioutil.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "CA Name: CN=Test CA") {
		t.Error("Policy missing CA Name")
	}
	if !strings.Contains(content, "Serial Number: 3039") { // 12345 hex = 0x3039
		t.Error("Policy missing serial number")
	}
	if !strings.Contains(content, "Key Algorithm: RSA-4096") {
		t.Error("Policy missing key algorithm")
	}
}

// TestIntegrationCAInit runs the full ca init command in a temp directory.
func TestIntegrationCAInit(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temporary directory
	tmpDir, err := ioutil.TempDir("", "micropki-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Write passphrase file
	passFile := filepath.Join(tmpDir, "pass.txt")
	if err := ioutil.WriteFile(passFile, []byte("test-pass\n"), 0600); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(tmpDir, "pki")
	logFile := filepath.Join(tmpDir, "log.txt")

	// Set up the arguments for the `ca init` subcommand
	ca.CaCmd.SetArgs([]string{
		"init",
		"--subject", "CN=Integration Test CA,O=Test",
		"--key-type", "rsa",
		"--key-size", "4096",
		"--passphrase-file", passFile,
		"--out-dir", outDir,
		"--validity-days", "3650",
		"--log-file", logFile,
	})

	// Execute the command
	if err := ca.CaCmd.Execute(); err != nil {
		t.Fatalf("ca init failed: %v", err)
	}

	// Verify files exist
	keyPath := filepath.Join(outDir, "private", "ca.key.pem")
	certPath := filepath.Join(outDir, "certs", "ca.cert.pem")
	policyPath := filepath.Join(outDir, "policy.txt")

	for _, path := range []string{keyPath, certPath, policyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("Expected file %s not found: %v", path, err)
		}
	}

	// Verify key permissions (on Unix-like)
	if info, err := os.Stat(keyPath); err == nil {
		if info.Mode().Perm() != 0600 {
			t.Errorf("Key permissions = %v, want 0600", info.Mode().Perm())
		}
	}

	// Verify certificate can be loaded and is self-signed
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("certificate PEM decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Self-signature verification failed: %v", err)
	}

	// Verify log file contains expected entries
	logData, err := ioutil.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	logContent := string(logData)
	expected := []string{
		"Starting Root CA initialization",
		"Key generation completed",
		"Certificate saved",
		"Root CA initialization completed successfully",
	}
	for _, s := range expected {
		if !strings.Contains(logContent, s) {
			t.Errorf("Log missing expected entry: %s", s)
		}
	}
}
