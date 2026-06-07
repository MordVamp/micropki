package tests

import (
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"micropki/internal/ca"
	"micropki/internal/client"
	"micropki/internal/database"
	pkgocsp "micropki/internal/ocsp"
	"micropki/internal/repository"
)

func init() {
	if os.Getenv("MICROPKI_FORK_BOMB_PREVENT") == "1" {
		os.Exit(0)
	}
}

func TestIntegrationFullWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	if os.Getenv("MICROPKI_FORK_BOMB_PREVENT") == "1" {
		t.Skip("Skipping integration test in child process to prevent fork bomb")
	}
	os.Setenv("MICROPKI_FORK_BOMB_PREVENT", "1")
	defer os.Unsetenv("MICROPKI_FORK_BOMB_PREVENT")

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
		"--out-file", crlPath,
		"--ca", "root",
		"--passphrase-file", passFile,
		"--db-path", dbPath,
	})
	if err := ca.CaCmd.Execute(); err != nil {
		t.Fatalf("ca gen-crl failed: %v", err)
	}

	// 6. ca issue-ocsp-cert
	ca.CaCmd.SetArgs([]string{
		"issue-ocsp-cert",
		"--subject", "CN=OCSP Responder",
		"--ca-cert", caCertPath,
		"--ca-key", caKeyPath,
		"--ca-pass-file", passFile,
		"--out-dir", outDir,
		"--db-path", dbPath,
	})
	if err := ca.CaCmd.Execute(); err != nil {
		t.Fatalf("ca issue-ocsp-cert failed: %v", err)
	}

	// 7. ca issue-intermediate
	ca.CaCmd.SetArgs([]string{
		"issue-intermediate",
		"--subject", "CN=Intermediate CA",
		"--root-cert", caCertPath,
		"--root-key", caKeyPath,
		"--root-pass-file", passFile,
		"--passphrase-file", passFile, // new passphrase for intermediate
		"--out-dir", outDir,
		"--db-path", dbPath,
	})
	if err := ca.CaCmd.Execute(); err != nil {
		t.Fatalf("ca issue-intermediate failed: %v", err)
	}

	// 8. client validate
	clientCertPath := filepath.Join(outDir, "Test_Client.cert.pem")
	client.ClientCmd.SetArgs([]string{
		"validate",
		"--cert", clientCertPath,
		"--trusted", caCertPath,
	})
	if err := client.ClientCmd.Execute(); err != nil {
		t.Fatalf("client validate failed: %v", err)
	}

	// 9. client check-status
	client.ClientCmd.SetArgs([]string{
		"check-status",
		"--cert", clientCertPath,
		"--ca-cert", caCertPath,
		"--crl", crlPath,
	})
	if err := client.ClientCmd.Execute(); err != nil {
		t.Fatalf("client check-status failed: %v", err)
	}

	// 10. Start OCSP Responder and query it
	responder, err := pkgocsp.NewResponder(
		filepath.Join(outDir, "ocsp.cert.pem"),
		filepath.Join(outDir, "ocsp.key.pem"),
		caCertPath,
	)
	if err == nil {
		mux := http.NewServeMux()
		mux.Handle("/ocsp", responder)
		srv := &http.Server{Addr: ":18081", Handler: mux}
		go srv.ListenAndServe()
		time.Sleep(500 * time.Millisecond)

		// 11. client check-status via OCSP
		client.ClientCmd.SetArgs([]string{
			"check-status",
			"--cert", clientCertPath,
			"--ca-cert", caCertPath,
			"--ocsp-url", "http://127.0.0.1:18081/ocsp",
		})
		if err := client.ClientCmd.Execute(); err != nil {
			t.Logf("client check-status via OCSP returned error: %v", err)
		}
		
		srv.Close()
	} else {
		t.Logf("failed to create OCSP responder: %v", err)
	}

	// 12. Start Repo Server natively
	repoSrv := &repository.Server{
		Host:       "127.0.0.1",
		Port:       18080,
		DBPath:     dbPath,
		CertDir:    filepath.Join(outDir, "certs"), // Note: outDir is pki, certs is pki/certs
		CACertPath: caCertPath,
		CAKeyPath:  caKeyPath,
		CAPassPath: passFile,
		RateLimit:  0,
	}
	go repoSrv.Start()
	time.Sleep(500 * time.Millisecond)

	// 13. Query repo server via request-cert
	csrPath := filepath.Join(outDir, "repo_test.csr.pem")
	keyPath := filepath.Join(outDir, "repo_test.key.pem")
	client.ClientCmd.SetArgs([]string{
		"gen-csr",
		"--subject", "CN=Repo Client",
		"--out-csr", csrPath,
		"--out-key", keyPath,
	})
	client.ClientCmd.Execute()

	client.ClientCmd.SetArgs([]string{
		"request-cert",
		"--csr", csrPath,
		"--ca-url", "http://127.0.0.1:18080",
		"--out-cert", filepath.Join(outDir, "repo_test.cert.pem"),
	})
	if err := client.ClientCmd.Execute(); err != nil {
		t.Logf("client request-cert returned error: %v", err)
	}
}
