package tests

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"micropki/internal/ca"
	"micropki/internal/database"
)

func TestIntegrationFullWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir, err := ioutil.TempDir("", "micropki-workflow")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	passFile := filepath.Join(tmpDir, "pass.txt")
	ioutil.WriteFile(passFile, []byte("test-pass\n"), 0600)

	outDir := filepath.Join(tmpDir, "pki")
	logFile := filepath.Join(tmpDir, "log.txt")
	dbPath := filepath.Join(outDir, "micropki.db")

	// 1. ca init
	ca.CaCmd.SetArgs([]string{
		"init",
		"--subject", "CN=Integration Test CA",
		"--key-type", "rsa",
		"--key-size", "4096",
		"--passphrase-file", passFile,
		"--out-dir", outDir,
		"--log-file", logFile,
	})
	if err := ca.CaCmd.Execute(); err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skipf("Skipping integration test due to CGO_ENABLED=0: %v", err)
		}
		t.Fatalf("ca init failed: %v", err)
	}

	// 2. ca issue-cert (Client)
	caCertPath := filepath.Join(outDir, "certs", "ca.cert.pem")
	caKeyPath := filepath.Join(outDir, "private", "ca.key.pem")
	
	ca.CaCmd.SetArgs([]string{
		"issue-cert",
		"--subject", "CN=Test Client",
		"--template", "client",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--ca-pass-file", passFile,
		"--out-dir", outDir,
		"--db-path", dbPath,
		"--log-file", logFile,
	})
	if err := ca.CaCmd.Execute(); err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skipf("Skipping integration test due to CGO_ENABLED=0: %v", err)
		}
		t.Fatalf("ca issue-cert failed: %v", err)
	}

	// 3. ca list-certs
	ca.CaCmd.SetArgs([]string{
		"list-certs",
		"--db-path", dbPath,
	})
	if err := ca.CaCmd.Execute(); err != nil {
		t.Fatalf("ca list-certs failed: %v", err)
	}

	// Get serial from DB
	database.InitDB(dbPath)
	records, _ := database.ListCertificates("")
	var targetSerial = "unknown"
	if len(records) > 0 {
		targetSerial = records[0].SerialHex
	}

	// 4. ca revoke
	ca.CaCmd.SetArgs([]string{
		"revoke",
		targetSerial,
		"--reason", "keyCompromise",
		"--db-path", dbPath,
	})
	if err := ca.CaCmd.Execute(); err != nil {
		t.Fatalf("ca revoke failed: %v", err)
	}

	// 5. ca gen-crl
	crlPath := filepath.Join(outDir, "crl.pem")
	ca.CaCmd.SetArgs([]string{
		"gen-crl",
		"--out", crlPath,
		"--db-path", dbPath,
		"--pki-dir", outDir,
	})
	if err := ca.CaCmd.Execute(); err != nil {
		t.Fatalf("ca gen-crl failed: %v", err)
	}
}
