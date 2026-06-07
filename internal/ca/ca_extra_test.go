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
		_ = CaCmd.Execute()
	}
}

func TestIssueCertSpecificErrors(t *testing.T) {
	// Let's set some global variables in issue-cert explicitly to trigger specific errors
	certCACert = "/dev/null/invalid"
	certCAKey = "/dev/null/invalid"
	certCAPassFile = "/dev/null/invalid"
	certTemplate = "invalid_template"
	certSubject = "CN=test"
	certDbPath = "/dev/null/invalid/db"
	_ = runIssueCert(issueCertCmd, []string{})

	// Same for intermediate
	intermediateRootCert = "/dev/null/invalid"
	intermediateRootKey = "/dev/null/invalid"
	_ = runIssueIntermediate(issueIntermediateCmd, []string{})

	// Same for gen_root
	rootOutDir = "/dev/null/invalid"
	_ = runInitRootCA(initCmd, []string{})

	// Same for ocsp
	ocspCACert = "/dev/null/invalid"
	_ = runIssueOCSPCert(issueOCSPCmd, []string{})

	// Same for crl
	crlPassFile = "/dev/null/invalid"
	_ = runGenCRL(genCRLCmd, []string{})
}
