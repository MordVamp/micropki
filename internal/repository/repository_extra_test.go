package repository

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleCertificate(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("GET", "/certificate/1234", nil)
	w := httptest.NewRecorder()
	srv.handleCertificate(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestHandleRequestCert(t *testing.T) {
	srv := &Server{}
	req := httptest.NewRequest("POST", "/request-cert?template=server", strings.NewReader(`{"csr": "fake"}`))
	req.Header.Set("X-API-Key", "changeme")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.handleRequestCert(w, req)
}
