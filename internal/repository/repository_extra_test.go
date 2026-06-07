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
