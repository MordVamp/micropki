package main

import (
	"bytes"
	"testing"
)

func TestCLIBoilerplate(t *testing.T) {
	// Execute all root commands with "--help" to cover the init() functions,
	// AddCommand() calls, and flag definitions in all cmd/micropki/*.go files.
	commands := []string{
		"ca", "client", "audit", "db", "ocsp", "repo",
	}

	for _, cmd := range commands {
		rootCmd.SetArgs([]string{cmd, "--help"})
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		
		err := rootCmd.Execute()
		if err != nil {
			t.Errorf("expected no error for '%s --help', got %v", cmd, err)
		}
	}
	
	// Also test main error path indirectly by passing an invalid command
	rootCmd.SetArgs([]string{"nonexistent-command-123"})
	err := rootCmd.Execute()
	if err == nil {
		t.Errorf("expected error for nonexistent command, got nil")
	}
}
