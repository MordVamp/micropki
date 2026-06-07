package client

import (
	"bytes"
	"testing"
)

func TestClientCommandsInvalidArgs(t *testing.T) {
	cmds := [][]string{
		{"gen-csr", "--out-csr", "/dev/null/invalid", "--out-key", "/dev/null/invalid", "--subject", "CN=invalid"},
		{"request-cert", "--csr", "/dev/null/invalid", "--ca-url", "http://invalid", "--out-cert", "/dev/null/invalid"},
		{"check-status", "--cert", "/dev/null/invalid", "--ca-cert", "/dev/null/invalid"},
		{"validate", "--cert", "/dev/null/invalid", "--trusted", "/dev/null/invalid"},
	}

	for _, args := range cmds {
		ClientCmd.SetArgs(args)
		var out bytes.Buffer
		ClientCmd.SetOut(&out)
		_ = ClientCmd.Execute()
	}
}

func TestClientSpecificErrors(t *testing.T) {
	// Directly call RunE to trigger specific variables
	csrOut = "/dev/null/invalid"
	csrKeyOut = "/dev/null/invalid"
	_ = runGenCSR(genCSRCmd, []string{})

	reqCSRPath = "/dev/null/invalid"
	reqOutCert = "/dev/null/invalid"
	_ = runRequestCert(requestCertCmd, []string{})

	chkCertPath = "/dev/null/invalid"
	chkCACertPath = "/dev/null/invalid"
	_ = runCheckStatus(checkStatusCmd, []string{})

	valCertPath = "/dev/null/invalid"
	valTrustedPath = "/dev/null/invalid"
	_ = runValidate(validateCmd, []string{})
}
