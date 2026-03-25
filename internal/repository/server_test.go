package repository

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRepositoryEndpoints(t *testing.T) {
	// Setup test directories
	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "certs")
	os.MkdirAll(certDir, 0700)
	
	rootCertPath := filepath.Join(certDir, "ca.cert.pem")
	os.WriteFile(rootCertPath, []byte("ROOT_PEM"), 0644)

	srv := &Server{
		Host:    "127.0.0.1",
		Port:    0,
		CertDir: certDir,
	}

	// Handle functions
	mux := http.NewServeMux()
	mux.HandleFunc("/ca/", srv.handleCA)
	mux.HandleFunc("/crl", srv.handleCRL)

	// Test CA Root Fetch
	req := httptest.NewRequest("GET", "/ca/root", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Errorf("Expected GET /ca/root to return 200, got %d", res.StatusCode)
	}

	// Test CRL Placeholder
	reqCRL := httptest.NewRequest("GET", "/crl", nil)
	wCRL := httptest.NewRecorder()
	mux.ServeHTTP(wCRL, reqCRL)
	
	resCRL := wCRL.Result()
	if resCRL.StatusCode != http.StatusNotFound {
		t.Errorf("Expected GET /crl to legitimately return 404 since the file isn't created in test mode, got %d", resCRL.StatusCode)
	}
}
