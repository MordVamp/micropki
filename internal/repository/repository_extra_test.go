package repository

import (
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"micropki/internal/database"
)

func TestHandleCertificate(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("GET", "/certificate/1234", nil)
	w := httptest.NewRecorder()
	srv.handleCertificate(w, req)
	// DB not initialized → 500 Internal Server Error
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestHandleCertificate_MethodNotAllowed(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("POST", "/certificate/abc", nil)
	w := httptest.NewRecorder()
	srv.handleCertificate(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleRequestCert_Unauthorized(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("POST", "/request-cert?template=server", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	// No X-API-Key header → should be unauthorized
	w := httptest.NewRecorder()
	srv.handleRequestCert(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleRequestCert_MissingTemplate(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("POST", "/request-cert", strings.NewReader(`{}`))
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleRequestCert(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing template, got %d", w.Code)
	}
}

func TestHandleRequestCert_MethodNotAllowed(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("GET", "/request-cert?template=server", nil)
	w := httptest.NewRecorder()
	srv.handleRequestCert(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleRequestCert_InvalidJSON(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("POST", "/request-cert?template=server", strings.NewReader(`NOT JSON`))
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleRequestCert(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHandleCA_Success(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := tmpDir + "/ca.cert.pem"
	os.WriteFile(certPath, []byte("fake cert content"), 0644)

	srv := &Server{CertDir: tmpDir}
	req := httptest.NewRequest("GET", "/ca/root", nil)
	w := httptest.NewRecorder()
	srv.handleCA(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleCRL_Success(t *testing.T) {
	tmpDir := t.TempDir()
	crlDir := tmpDir + "/crl"
	os.MkdirAll(crlDir, 0755)
	crlPath := crlDir + "/root.crl.pem"
	os.WriteFile(crlPath, []byte("fake crl content"), 0644)

	srv := &Server{CertDir: tmpDir + "/certs"} // parent of crl
	req := httptest.NewRequest("GET", "/crl?ca=root", nil)
	w := httptest.NewRecorder()
	srv.handleCRL(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHandleCertificate_Success(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"
	
	err := database.InitDB(dbPath)
	if err != nil {
		t.Skip("Skipping DB test (CGO disabled?)")
	}

	database.InsertCertificate(big.NewInt(9999), "CN=Test", "CN=Root", time.Now(), time.Now().Add(time.Hour), []byte("test cert content"))

	cert, err := database.GetCertificateBySerial("270f")
	t.Logf("Local lookup for 270f: cert=%v, err=%v", cert, err)

	srv := &Server{}
	req := httptest.NewRequest("GET", "/certificate/270f", nil)
	w := httptest.NewRecorder()
	srv.handleCertificate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
