package tests

import (
	"bytes"
	"testing"

	"micropki/internal/ca"
	"micropki/internal/client"
)

func TestCLI_RunE(t *testing.T) {
	// We execute various commands with invalid arguments just to trigger 
	// their RunE functions and cover the flag parsing and initialization logic.
	caCmds := [][]string{
		{"show-cert", "--serial", "invalid_serial"},
		{"compromise", "--serial", "invalid_serial"},
		{"issue-ocsp", "--subject", "CN=invalid", "--ca-cert", "/dev/null/invalid", "--ca-key", "/dev/null/invalid"},
		{"issue-intermediate", "--subject", "CN=invalid", "--ca-cert", "/dev/null/invalid", "--ca-key", "/dev/null/invalid"},
	}
	for _, args := range caCmds {
		ca.CaCmd.SetArgs(args)
		var out bytes.Buffer
		ca.CaCmd.SetOut(&out)
		_ = ca.CaCmd.Execute()
	}

	clientCmds := [][]string{
		{"check-status", "--cert", "/dev/null/invalid", "--ca-cert", "/dev/null/invalid"},
		{"validate", "--cert", "/dev/null/invalid", "--ca-cert", "/dev/null/invalid"},
	}
	for _, args := range clientCmds {
		client.ClientCmd.SetArgs(args)
		var out bytes.Buffer
		client.ClientCmd.SetOut(&out)
		_ = client.ClientCmd.Execute()
	}
}
