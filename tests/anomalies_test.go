package tests

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"micropki/internal/client"
	"micropki/internal/crypto"
	"micropki/internal/utils"
)

func TestNetworkAnomalies(t *testing.T) {
	// 1. Connection Refused / Invalid URL
	csrPath := filepath.Join(t.TempDir(), "test.csr")
	// write dummy
	utils.SafeWriteFile(csrPath, []byte("dummy csr"), 0644, false)
	
	client.ClientCmd.SetArgs([]string{
		"request-cert",
		"--csr", csrPath,
		"--ca-url", "http://127.0.0.1:0", // Invalid port
	})
	
	err := client.ClientCmd.Execute()
	if err == nil {
		t.Error("expected network error on dead port")
	}
}

func TestCryptoAnomalies(t *testing.T) {
	// 1. Decrypt with invalid passphrase
	priv, _ := crypto.GenerateRSAKey(2048)
	encryptedPEM, _ := crypto.EncryptPrivateKey(priv, []byte("correct-pass"))
	
	_, err := crypto.DecryptPrivateKey(encryptedPEM, []byte("wrong-pass"))
	if err == nil {
		t.Error("expected error decrypting with wrong passphrase")
	}

	// 2. Decrypt garbage data
	_, err = crypto.DecryptPrivateKey([]byte("-----BEGIN RSA PRIVATE KEY-----\ngarbage\n-----END RSA PRIVATE KEY-----"), []byte("pass"))
	if err == nil {
		t.Error("expected error decrypting garbage PEM")
	}

	// 3. Invalid PEM format entirely
	_, err = crypto.DecryptPrivateKey([]byte("not a pem"), []byte("pass"))
	if err == nil {
		t.Error("expected error on non-PEM data")
	}
	
	// 4. Encrypt with unsupported key type
	// Try to encrypt an invalid key interface type
	_, err = crypto.EncryptPrivateKey("not a key", []byte("pass"))
	if err == nil {
		t.Error("expected error encrypting unsupported key type")
	}
}

func TestRequestCertAnomalies(t *testing.T) {
	// Mock server returning 500
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal server error"}`))
	}))
	defer ts.Close()

	csrPath := filepath.Join(t.TempDir(), "test.csr")
	// Let's create a valid CSR first
	client.ClientCmd.SetArgs([]string{
		"gen-csr",
		"--subject", "CN=Test",
		"--out-csr", csrPath,
		"--out-key", filepath.Join(t.TempDir(), "test.key"),
	})
	_ = client.ClientCmd.Execute()

	// Call request-cert with 500 server
	client.ClientCmd.SetArgs([]string{
		"request-cert",
		"--csr", csrPath,
		"--ca-url", ts.URL,
		"--out-cert", filepath.Join(t.TempDir(), "test.cert"),
	})
	err := client.ClientCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "CA Repository returned error (500)") {
		t.Errorf("expected 500 error, got %v", err)
	}
}
