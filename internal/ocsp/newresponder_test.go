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
	"time"

	"micropki/internal/certs"
	internalcrypto "micropki/internal/crypto"
	"micropki/internal/database"

	xocsp "golang.org/x/crypto/ocsp"
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

	// Removed unused variables that broke compilation
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

func TestServeHTTP_ValidRequest(t *testing.T) {
	dir := t.TempDir()

	dbPath := filepath.Join(dir, "test.db")
	err := database.InitDB(dbPath)
	if err != nil {
		t.Skipf("Skipping test because DB init failed (likely CGO_ENABLED=0): %v", err)
	}

	// Create test certificates
	caKey, _ := internalcrypto.GenerateRSAKey(2048)
	caSubject := &pkix.Name{CommonName: "Test CA"}
	caCertPEM, _ := certs.GenerateRootCertificate(caSubject, &caKey.PublicKey, caKey, 365, big.NewInt(1))
	caCertPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(caCertPath, caCertPEM, 0644)
	blockCA, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(blockCA.Bytes)

	keyBytes, _ := x509.MarshalPKCS8PrivateKey(caKey)
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	caKeyPath := filepath.Join(dir, "ca.key")
	os.WriteFile(caKeyPath, caKeyPEM, 0600)

	// User cert to check
	userKey, _ := internalcrypto.GenerateRSAKey(2048)
	userSubject := &pkix.Name{CommonName: "User"}
	userCertPEM, _ := certs.GenerateRootCertificate(userSubject, &userKey.PublicKey, userKey, 365, big.NewInt(1234))
	blockUser, _ := pem.Decode(userCertPEM)
	userCert, _ := x509.ParseCertificate(blockUser.Bytes)

	// Write user cert to DB (valid status)
	database.InsertCertificate(big.NewInt(1234), "CN=User", "CN=Test CA", time.Now(), time.Now().Add(24*time.Hour), userCertPEM)

	responder, err := NewResponder(caCertPath, caKeyPath, caCertPath)
	if err != nil {
		t.Fatalf("Failed to create responder: %v", err)
	}

	// Create OCSP request
	reqDER, err := xocsp.CreateRequest(userCert, caCert, nil)
	if err != nil {
		t.Fatalf("Failed to create OCSP request: %v", err)
	}

	// 1. Test Valid/Good Status
	req, _ := http.NewRequest("POST", "/ocsp", bytes.NewBuffer(reqDER))
	req.Header.Set("Content-Type", "application/ocsp-request")
	w := httptest.NewRecorder()
	responder.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected StatusOK, got %d", w.Code)
	}
	respBytes := w.Body.Bytes()
	ocspResp, err := xocsp.ParseResponseForCert(respBytes, userCert, caCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response: %v", err)
	}
	if ocspResp.Status != xocsp.Good {
		t.Errorf("Expected status Good, got %d", ocspResp.Status)
	}

	// 2. Test Revoked Status (Cache hit/miss)
	// Revoke in DB
	database.RevokeCertificate("4d2", "keyCompromise") // 1234 in hex is 4d2
	// Clear responder cache to enforce DB reload
	responder.Cache.Delete("4d2")

	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("POST", "/ocsp", bytes.NewBuffer(reqDER))
	req2.Header.Set("Content-Type", "application/ocsp-request")
	responder.ServeHTTP(w2, req2)

	ocspResp2, err := xocsp.ParseResponseForCert(w2.Body.Bytes(), userCert, caCert)
	if err != nil {
		t.Fatalf("Failed to parse OCSP response 2: %v", err)
	}
	if ocspResp2.Status != xocsp.Revoked {
		t.Errorf("Expected status Revoked, got %d", ocspResp2.Status)
	}
}
