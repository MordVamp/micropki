package policy

import (
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
)

func TestWrite(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/policy.txt"
	name := &pkix.Name{CommonName: "TestRoot"}
	serial := big.NewInt(1234)

	err := Write(path, name, serial, 365, "rsa", 4096)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil || len(content) == 0 {
		t.Fatalf("Failed to read created policy file: %v", err)
	}
}

func TestAppendIntermediate(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/policy.txt"
	name := &pkix.Name{CommonName: "TestRoot"}
	serial := big.NewInt(1234)

	_ = Write(path, name, serial, 365, "rsa", 4096)

	intName := &pkix.Name{CommonName: "TestInt"}
	err := AppendIntermediate(path, intName, big.NewInt(5678), 180, "rsa", 2048, 0, name)
	if err != nil {
		t.Fatalf("AppendIntermediate failed: %v", err)
	}
}

func TestLoadConfig(t *testing.T) {
	// Empty path
	LoadConfig("")

	// Non-existent path
	LoadConfig("nonexistent.yaml")

	// Valid path
	tmpDir := t.TempDir()
	path := tmpDir + "/config.yaml"
	yamlContent := `
validity:
  root_max_days: 999
`
	os.WriteFile(path, []byte(yamlContent), 0644)
	LoadConfig(path)
	if CurrentConfig.Validity.RootMaxDays != 999 {
		t.Errorf("expected 999, got %d", CurrentConfig.Validity.RootMaxDays)
	}
	
	// Invalid YAML
	badPath := tmpDir + "/bad.yaml"
	os.WriteFile(badPath, []byte("invalid:\nyaml: ["), 0644)
	LoadConfig(badPath)
}
