package policy

import (
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyWriteAndAppend(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "policy.txt")
	name := &pkix.Name{CommonName: "Test CA"}
	serial := big.NewInt(1234)

	err := Write(tmpFile, name, serial, 365, "rsa", 2048)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data, _ := os.ReadFile(tmpFile)
	if len(data) == 0 {
		t.Errorf("Expected policy text, got empty")
	}

	err = AppendIntermediate(tmpFile, name, serial, 365, "ecc", 384, 0, name)
	if err != nil {
		t.Fatalf("AppendIntermediate failed: %v", err)
	}
}
