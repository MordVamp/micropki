package ocsp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponderHTTPMethods(t *testing.T) {
	// A mock responder missing valid keys will still reject GETs correctly
	responder := &Responder{}

	req, err := http.NewRequest("GET", "/ocsp", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(responder.ServeHTTP)

	handler.ServeHTTP(rr, req)

	// We expect 405 Method Not Allowed for GET
	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusMethodNotAllowed)
	}
}

func TestResponderInvalidMediaType(t *testing.T) {
	responder := &Responder{}

	body := []byte("invalid content")
	req, err := http.NewRequest("POST", "/ocsp", bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	// Missing Content-Type: application/ocsp-request
	req.Header.Set("Content-Type", "text/plain")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(responder.ServeHTTP)

	handler.ServeHTTP(rr, req)

	// We expect 415 Unsupported Media Type
	if status := rr.Code; status != http.StatusUnsupportedMediaType {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnsupportedMediaType)
	}
}
