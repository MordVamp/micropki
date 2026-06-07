package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createTestCerts(t *testing.T) (root, inter, leaf *x509.Certificate, rootKey, interKey, leafKey *rsa.PrivateKey) {
	var err error
	rootKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	interKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()

	// Root template
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	// Intermediate template
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, err = x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}

	// Leaf template
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return
}

func createTestCRL(t *testing.T, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, revokedSerials []int64) []byte {
	var revoked []pkix.RevokedCertificate
	for _, s := range revokedSerials {
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   big.NewInt(s),
			RevocationTime: time.Now(),
		})
	}
	crlTemplate := &x509.RevocationList{
		Number:              big.NewInt(1),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(24 * time.Hour),
		RevokedCertificates: revoked,
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, issuer, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return crlBytes
}

func TestBuildChain(t *testing.T) {
	root, inter, leaf, _, interKey, _ := createTestCerts(t)

	// Valid chain building
	chain, err := buildChain(leaf, []*x509.Certificate{inter}, []*x509.Certificate{root})
	if err != nil {
		t.Fatalf("Failed to build chain: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("Expected chain length 3, got %d", len(chain))
	}
	if chain[0].Subject.CommonName != "Leaf Cert" ||
		chain[1].Subject.CommonName != "Intermediate CA" ||
		chain[2].Subject.CommonName != "Root CA" {
		t.Errorf("Invalid chain order")
	}

	// Missing intermediate
	_, err = buildChain(leaf, []*x509.Certificate{}, []*x509.Certificate{root})
	if err == nil {
		t.Errorf("Expected failure when intermediate is missing")
	}

	// Cycle detection (untrusted intermediate is signed by leaf - fake cycle)
	// We build A signed by B, and B signed by A.
	aTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: "Cert A"},
	}
	bTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "Cert B"},
	}
	aDER, _ := x509.CreateCertificate(rand.Reader, aTemplate, bTemplate, &interKey.PublicKey, interKey)
	a, _ := x509.ParseCertificate(aDER)
	bDER, _ := x509.CreateCertificate(rand.Reader, bTemplate, aTemplate, &interKey.PublicKey, interKey)
	b, _ := x509.ParseCertificate(bDER)

	_, err = buildChain(a, []*x509.Certificate{b, a}, []*x509.Certificate{root})
	if err == nil {
		t.Errorf("Expected cycle detection failure")
	}
}

func TestValidateChainCryptographically(t *testing.T) {
	root, inter, leaf, _, _, _ := createTestCerts(t)
	chain := []*x509.Certificate{leaf, inter, root}
	now := time.Now()

	// 1. Success case
	err := validateChainCryptographically(chain, now)
	if err != nil {
		t.Fatalf("Expected cryptographic validation success, got: %v", err)
	}

	// 2. Out of bounds time (Leaf)
	err = validateChainCryptographically(chain, now.Add(48*time.Hour))
	if err == nil {
		t.Errorf("Expected error for out of bounds time")
	}

	// 3. Invalid signature (Corrupted chain signature)
	// We swap the root cert with another key-based cert to invalidate the signature
	badRootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	badRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Bad Root CA"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	badRootDER, _ := x509.CreateCertificate(rand.Reader, badRootTemplate, badRootTemplate, &badRootKey.PublicKey, badRootKey)
	badRoot, _ := x509.ParseCertificate(badRootDER)
	badChain := []*x509.Certificate{leaf, inter, badRoot}
	err = validateChainCryptographically(badChain, now)
	if err == nil {
		t.Errorf("Expected signature check failure")
	}

	// 4. Missing IsCA constraint on issuer
	// We sign intermediate with a non-CA certificate
	nonCAKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	nonCATemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "Non-CA"},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		IsCA:         false, // Not a CA
	}
	nonCADER, _ := x509.CreateCertificate(rand.Reader, nonCATemplate, nonCATemplate, &nonCAKey.PublicKey, nonCAKey)
	nonCA, _ := x509.ParseCertificate(nonCADER)

	interDER2, _ := x509.CreateCertificate(rand.Reader, inter, nonCA, &inter.PublicKey, nonCAKey)
	inter2, _ := x509.ParseCertificate(interDER2)
	badCAChain := []*x509.Certificate{leaf, inter2, nonCA}
	err = validateChainCryptographically(badCAChain, now)
	if err == nil {
		t.Errorf("Expected IsCA validation failure")
	}
}

func TestResolveRevocationLocalCRL(t *testing.T) {
	_, inter, leaf, _, interKey, _ := createTestCerts(t)

	tempDir := t.TempDir()
	crlFile := filepath.Join(tempDir, "test.crl")

	// 1. CRL not containing Leaf serial -> status good
	crlBytesGood := createTestCRL(t, inter, interKey, []int64{999})
	err := os.WriteFile(crlFile, crlBytesGood, 0644)
	if err != nil {
		t.Fatal(err)
	}

	status, _, err := resolveRevocation(leaf, inter, crlFile, false)
	if err != nil {
		t.Fatalf("resolveRevocation failed: %v", err)
	}
	if status != "good" {
		t.Errorf("Expected status 'good', got %q", status)
	}

	// 2. CRL containing Leaf serial -> status revoked
	crlBytesRevoked := createTestCRL(t, inter, interKey, []int64{3}) // Leaf serial is 3
	err = os.WriteFile(crlFile, crlBytesRevoked, 0644)
	if err != nil {
		t.Fatal(err)
	}

	status, _, err = resolveRevocation(leaf, inter, crlFile, false)
	if err != nil {
		t.Fatalf("resolveRevocation failed: %v", err)
	}
	if status != "revoked" {
		t.Errorf("Expected status 'revoked', got %q", status)
	}

	// 3. PEM format CRL decode fallback
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytesRevoked})
	err = os.WriteFile(crlFile, pemBytes, 0644)
	if err != nil {
		t.Fatal(err)
	}

	status, _, err = resolveRevocation(leaf, inter, crlFile, false)
	if err != nil {
		t.Fatalf("resolveRevocation failed: %v", err)
	}
	if status != "revoked" {
		t.Errorf("Expected status 'revoked', got %q", status)
	}

	// 4. Invalid CRL file path
	_, _, err = resolveRevocation(leaf, inter, "non-existent-path-12345", false)
	if err == nil {
		t.Errorf("Expected error for non-existent CRL path")
	}
}
