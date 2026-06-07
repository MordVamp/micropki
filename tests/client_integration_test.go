package tests

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"micropki/internal/client"
)

func TestClientIntegrationFull(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	tmpDir, _ := ioutil.TempDir("", "micropki-client")
	defer os.RemoveAll(tmpDir)

	csrPath := filepath.Join(tmpDir, "test.csr")
	keyPath := filepath.Join(tmpDir, "test.key")

	client.ClientCmd.SetArgs([]string{
		"gen-csr",
		"--subject", "CN=Client Gen",
		"--key-type", "rsa",
		"--key-size", "2048",
		"--out", csrPath,
		"--key-out", keyPath,
	})
	
	if err := client.ClientCmd.Execute(); err != nil {
		t.Fatalf("client gen-csr failed: %v", err)
	}
	
	if _, err := os.Stat(csrPath); err != nil {
		t.Errorf("Expected CSR not found")
	}
}
