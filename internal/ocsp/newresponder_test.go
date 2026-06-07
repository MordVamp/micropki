package ocsp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
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

	block, _ := pem.Decode(ocspCertPEM)
	ocspCert, _ := x509.ParseCertificate(block.Bytes)

	blockCA, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(blockCA.Bytes)

	// We can't import golang.org/x/crypto/ocsp because it shadows internal ocsp package?
	// Wait, we can alias it or not use it if we don't need it.
	// Actually we just need an HTTP POST with bad body to trigger 400
	reqPost, _ := http.NewRequest("POST", "/ocsp", bytes.NewBuffer([]byte("bad request")))
	reqPost.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	responder.ServeHTTP(w, reqPost)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request, got %d", w.Code)
	}
}
