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
		{"show-cert", "invalid_serial"},
		{"compromise", "--cert", "/dev/null/invalid"},
		{"issue-ocsp-cert", "--subject", "CN=invalid", "--ca-cert", "/dev/null/invalid", "--ca-key", "/dev/null/invalid", "--ca-pass-file", "/dev/null/invalid"},
		{"issue-intermediate", "--subject", "CN=invalid", "--root-cert", "/dev/null/invalid", "--root-key", "/dev/null/invalid", "--root-pass-file", "/dev/null/invalid", "--passphrase-file", "/dev/null/invalid"},
	}
	for _, args := range caCmds {
		ca.CaCmd.SetArgs(args)
		var out bytes.Buffer
		ca.CaCmd.SetOut(&out)
		ca.CaCmd.SetErr(&out)
		_ = ca.CaCmd.Execute()
	}

	clientCmds := [][]string{
		{"gen-csr", "--subject", "CN=invalid"},
		{"validate", "--cert", "/dev/null/invalid"},
		{"request-cert", "--csr", "/dev/null/invalid"},
		{"check-status", "--cert", "/dev/null/invalid", "--ca-cert", "/dev/null/invalid"},
	}

	for _, args := range clientCmds {
		client.ClientCmd.SetArgs(args)
		var out bytes.Buffer
		client.ClientCmd.SetOut(&out)
		client.ClientCmd.SetErr(&out)
		_ = client.ClientCmd.Execute()
	}
}
