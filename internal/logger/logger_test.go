package logger

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogger(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.log")

	err := Init(tmpFile)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	Info("Test info")
	Warning("Test warning")
	Error("Test error")

	Close()

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read log: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("Log file is empty")
	}

	// Test stderr branch
	err = Init("")
	if err != nil {
		t.Fatalf("Init (stderr) failed: %v", err)
	}
	Info("Test info to stderr")
}
