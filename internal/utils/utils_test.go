package utils

import (
	"path/filepath"
	"testing"
)

func TestUtils(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	err := SafeWriteFile(tmpFile, []byte("data"), 0644, false)
	if err != nil {
		t.Fatalf("SafeWriteFile (new): %v", err)
	}
	
	err = SafeWriteFile(tmpFile, []byte("data2"), 0644, false)
	if err == nil {
		t.Fatalf("Expected error when file exists and force=false")
	}
	
	err = SafeWriteFile(tmpFile, []byte("data2"), 0644, true)
	if err != nil {
		t.Fatalf("SafeWriteFile (force): %v", err)
	}
}
