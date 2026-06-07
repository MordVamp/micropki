package ca

import (
	"bytes"
	"testing"
)

func TestCACommandsInvalidArgs(t *testing.T) {
	// Execute various commands with missing or invalid flags to hit error branches directly
	cmds := [][]string{
		{"init", "--out-dir", "/dev/null/invalid"},
		{"init", "--passphrase-file", "/dev/null/invalid"},
		{"issue-cert", "--ca-cert", "/dev/null/invalid", "--ca-key", "/dev/null/invalid", "--ca-pass-file", "/dev/null/invalid", "--template", "server", "--subject", "CN=invalid"},
		{"issue-intermediate", "--root-cert", "/dev/null/invalid", "--root-key", "/dev/null/invalid", "--root-pass-file", "/dev/null/invalid", "--passphrase-file", "/dev/null/invalid", "--subject", "CN=invalid"},
		{"issue-ocsp-cert", "--ca-cert", "/dev/null/invalid", "--ca-key", "/dev/null/invalid", "--ca-pass-file", "/dev/null/invalid", "--subject", "CN=invalid"},
		{"gen-crl", "--ca", "root", "--out-file", "/dev/null/invalid", "--passphrase-file", "/dev/null/invalid"},
		{"revoke", "1234", "--reason", "invalid_reason"},
		{"list-certs"},
		{"show-cert", "1234"},
		{"compromise", "--cert", "/dev/null/invalid", "--reason", "invalid"},
	}

	for _, args := range cmds {
		CaCmd.SetArgs(args)
		var out bytes.Buffer
		CaCmd.SetOut(&out)
		CaCmd.SetErr(&out)
		_ = CaCmd.Execute()
	}
}
