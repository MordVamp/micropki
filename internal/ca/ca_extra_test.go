package ca

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"micropki/internal/logger"
	"micropki/internal/database"
)

func init() {
	logger.SilenceStderr = true
}

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

func TestValidateIssueIntermediateArgs(t *testing.T) {
	// Create some temp files to satisfy os.Stat checks
	tempDir := t.TempDir()
	validFile := filepath.Join(tempDir, "valid.txt")
	os.WriteFile(validFile, []byte("test"), 0644)

	// Save original globals
	origSubject := interSubject
	origKeyType := interKeyType
	origKeySize := interKeySize
	origValidity := interValidityDays
	origPathLen := interPathLen
	origRootCert := interRootCert
	origRootKey := interRootKey
	origRootPassFile := interRootPassFile
	origPassphraseFile := interPassphraseFile
	origUSBPath := interUSBPath

	defer func() {
		interSubject = origSubject
		interKeyType = origKeyType
		interKeySize = origKeySize
		interValidityDays = origValidity
		interPathLen = origPathLen
		interRootCert = origRootCert
		interRootKey = origRootKey
		interRootPassFile = origRootPassFile
		interPassphraseFile = origPassphraseFile
		interUSBPath = origUSBPath
	}()

	// 1. Subject empty
	interSubject = ""
	if err := validateIssueIntermediateArgs(); err == nil || err.Error() != "subject cannot be empty" {
		t.Errorf("Expected subject empty error, got: %v", err)
	}
	interSubject = "CN=Test"

	// 2. KeyType invalid
	interKeyType = "invalid"
	if err := validateIssueIntermediateArgs(); err == nil || err.Error() != "key-type must be 'rsa' or 'ecc'" {
		t.Errorf("Expected key-type error, got: %v", err)
	}
	interKeyType = "rsa"

	// 3. RSA KeySize too small
	interKeySize = 1024
	if err := validateIssueIntermediateArgs(); err == nil || !strings.Contains(err.Error(), "RSA key size must be") {
		t.Errorf("Expected RSA key size error, got: %v", err)
	}
	interKeySize = 4096

	// 4. ECC KeySize too small
	interKeyType = "ecc"
	interKeySize = 128
	if err := validateIssueIntermediateArgs(); err == nil || !strings.Contains(err.Error(), "ECC key size must be") {
		t.Errorf("Expected ECC key size error, got: %v", err)
	}
	interKeyType = "rsa"
	interKeySize = 4096

	// 5. Validity negative
	interValidityDays = -1
	if err := validateIssueIntermediateArgs(); err == nil || err.Error() != "validity-days must be positive" {
		t.Errorf("Expected validity-days error, got: %v", err)
	}
	interValidityDays = 365

	// 6. PathLen negative
	interPathLen = -1
	if err := validateIssueIntermediateArgs(); err == nil || err.Error() != "pathlen cannot be negative" {
		t.Errorf("Expected pathlen error, got: %v", err)
	}
	interPathLen = 0

	// 7. RootCert file missing
	interRootCert = filepath.Join(tempDir, "missing.txt")
	if err := validateIssueIntermediateArgs(); err == nil || !strings.Contains(err.Error(), "root certificate file issue") {
		t.Errorf("Expected root cert file error, got: %v", err)
	}
	interRootCert = validFile

	// 8. RootKey file missing
	interRootKey = filepath.Join(tempDir, "missing.txt")
	if err := validateIssueIntermediateArgs(); err == nil || !strings.Contains(err.Error(), "root key file issue") {
		t.Errorf("Expected root key file error, got: %v", err)
	}
	interRootKey = validFile

	// 9. RootPassFile missing
	interRootPassFile = filepath.Join(tempDir, "missing.txt")
	if err := validateIssueIntermediateArgs(); err == nil || !strings.Contains(err.Error(), "root passphrase file issue") {
		t.Errorf("Expected root pass file error, got: %v", err)
	}
	interRootPassFile = validFile

	// 10. PassphraseFile missing
	interPassphraseFile = filepath.Join(tempDir, "missing.txt")
	if err := validateIssueIntermediateArgs(); err == nil || !strings.Contains(err.Error(), "intermediate passphrase file issue") {
		t.Errorf("Expected intermediate pass file error, got: %v", err)
	}
	interPassphraseFile = validFile

	// 11. Success case
	if err := validateIssueIntermediateArgs(); err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
}

func TestCACommandsFullWorkflow(t *testing.T) {
	tempDir := t.TempDir()

	dbPath := filepath.Join(tempDir, "micropki.db")
	err := database.InitDB(dbPath)
	if err != nil {
		t.Skip("Skipping because SQLite requires CGO")
	}

	// Redirect stdout to avoid polluting test logs with CLI output (like large certificates)
	oldStdout := os.Stdout
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0666)
	os.Stdout = devNull
	defer func() {
		os.Stdout = oldStdout
		devNull.Close()
	}()

	passphraseFile := filepath.Join(tempDir, "passphrase.txt")
	os.WriteFile(passphraseFile, []byte("password123"), 0644)

	// 1. Run 'ca init'
	initArgs := []string{
		"init",
		"--subject", "CN=Root CA,O=Test,C=US",
		"--passphrase-file", passphraseFile,
		"--out-dir", tempDir,
		"--force",
	}
	CaCmd.SetArgs(initArgs)
	if err := CaCmd.Execute(); err != nil {
		t.Fatalf("ca init failed: %v", err)
	}

	// 2. Run 'ca issue-intermediate'
	rootCert := filepath.Join(tempDir, "certs", "ca.cert.pem")
	rootKey := filepath.Join(tempDir, "private", "ca.key.pem")
	interPassFile := filepath.Join(tempDir, "inter_pass.txt")
	os.WriteFile(interPassFile, []byte("interpass123"), 0644)

	interArgs := []string{
		"issue-intermediate",
		"--root-cert", rootCert,
		"--root-key", rootKey,
		"--root-pass-file", passphraseFile,
		"--subject", "CN=Intermediate CA,O=Test,C=US",
		"--passphrase-file", interPassFile,
		"--out-dir", tempDir,
		"--db-path", dbPath,
		"--force",
	}
	CaCmd.SetArgs(interArgs)
	if err := CaCmd.Execute(); err != nil {
		t.Fatalf("ca issue-intermediate failed: %v", err)
	}

	// 3. Run 'ca issue-cert' for server
	interCert := filepath.Join(tempDir, "certs", "intermediate.cert.pem")
	interKey := filepath.Join(tempDir, "private", "intermediate.key.pem")
	certArgs := []string{
		"issue-cert",
		"--ca-cert", interCert,
		"--ca-key", interKey,
		"--ca-pass-file", interPassFile,
		"--template", "server",
		"--subject", "CN=localhost",
		"--san", "dns:localhost,ip:127.0.0.1",
		"--out-dir", filepath.Join(tempDir, "certs"),
		"--db-path", dbPath,
		"--force",
	}
	CaCmd.SetArgs(certArgs)
	if err := CaCmd.Execute(); err != nil {
		t.Fatalf("ca issue-cert (server) failed: %v", err)
	}

	// 4. Run 'ca issue-ocsp-cert'
	ocspArgs := []string{
		"issue-ocsp-cert",
		"--ca-cert", interCert,
		"--ca-key", interKey,
		"--ca-pass-file", interPassFile,
		"--subject", "CN=OCSP Responder",
		"--out-dir", filepath.Join(tempDir, "certs"),
		"--db-path", dbPath,
	}
	CaCmd.SetArgs(ocspArgs)
	if err := CaCmd.Execute(); err != nil {
		t.Fatalf("ca issue-ocsp-cert failed: %v", err)
	}

	// Get a serial from database to show and revoke
	records, err := database.ListCertificates("")
	if err != nil || len(records) == 0 {
		t.Fatalf("No certificates in DB: %v", err)
	}
	serialHex := records[0].SerialHex

	// 5. Run 'ca list-certs'
	listArgs := []string{"list-certs", "--db-path", dbPath}
	CaCmd.SetArgs(listArgs)
	if err := CaCmd.Execute(); err != nil {
		t.Fatalf("ca list-certs failed: %v", err)
	}

	// 6. Run 'ca show-cert'
	showArgs := []string{"show-cert", serialHex, "--db-path", dbPath}
	CaCmd.SetArgs(showArgs)
	if err := CaCmd.Execute(); err != nil {
		t.Fatalf("ca show-cert failed: %v", err)
	}

	// 7. Run 'ca revoke'
	revokeArgs := []string{
		"revoke", serialHex,
		"--reason", "keyCompromise",
		"--db-path", dbPath,
	}
	CaCmd.SetArgs(revokeArgs)
	if err := CaCmd.Execute(); err != nil {
		t.Fatalf("ca revoke failed: %v", err)
	}

	// 8. Run 'ca gen-crl'
	genCrlArgs := []string{
		"gen-crl",
		"--ca", "intermediate",
		"--passphrase-file", interPassFile,
		"--db-path", dbPath,
		"--out-file", filepath.Join(tempDir, "crl.pem"),
		"--force",
	}
	CaCmd.SetArgs(genCrlArgs)
	if err := CaCmd.Execute(); err != nil {
		t.Fatalf("ca gen-crl failed: %v", err)
	}

	// 9. Run 'ca compromise'
	compromiseArgs := []string{
		"compromise",
		"--cert", filepath.Join(tempDir, "certs", "localhost.cert.pem"),
		"--reason", "keyCompromise",
		"--db-path", dbPath,
	}
	CaCmd.SetArgs(compromiseArgs)
	if err := CaCmd.Execute(); err != nil {
		t.Fatalf("ca compromise failed: %v", err)
	}
}
