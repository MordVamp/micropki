package client

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchResourceBytes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mock data"))
	}))
	defer ts.Close()

	data, err := fetchResourceBytes(ts.URL)
	if err != nil {
		t.Fatalf("fetchResourceBytes failed: %v", err)
	}
	if string(data) != "mock data" {
		t.Errorf("expected mock data, got %s", string(data))
	}
	
	_, err = fetchResourceBytes("http://127.0.0.1:0/invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestLoadCertificate(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "cert.pem")
	os.WriteFile(tmpFile, []byte("invalid cert"), 0644)
	
	_, err := loadCertificate(tmpFile)
	if err == nil {
		t.Error("expected error for invalid cert")
	}
	
	certs, err := loadCertificates(tmpFile)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
	
	_, err = loadCertificate("nonexistent.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
