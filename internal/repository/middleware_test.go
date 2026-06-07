package repository

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewares(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	chained := corsMiddleware(loggingMiddleware(handler))

	// Test OPTIONS
	reqOpt := httptest.NewRequest("OPTIONS", "/test", nil)
	wOpt := httptest.NewRecorder()
	chained.ServeHTTP(wOpt, reqOpt)
	if wOpt.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", wOpt.Code)
	}

	// Test GET
	reqGet := httptest.NewRequest("GET", "/test", nil)
	wGet := httptest.NewRecorder()
	chained.ServeHTTP(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Errorf("expected 200 for GET, got %d", wGet.Code)
	}
}
