package crl

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"micropki/internal/certs"
	internalcrypto "micropki/internal/crypto"
	"micropki/internal/database"
)

func TestGenerateCRL(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	err := database.InitDB(dbPath)
	if err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skipf("Skipping database test due to CGO_ENABLED=0: %v", err)
		}
		t.Fatalf("InitDB failed: %v", err)
	}
	defer os.Remove(dbPath)

	key, _ := internalcrypto.GenerateRSAKey(2048)
	subject := &pkix.Name{CommonName: "Test CRL CA"}
	serial := big.NewInt(1)
	certPEM, _ := certs.GenerateRootCertificate(subject, &key.PublicKey, key, 365, serial)

	block, _ := pem.Decode(certPEM)
	caCert, _ := x509.ParseCertificate(block.Bytes)

	subjectStr := caCert.Subject.String()
	serialFake := big.NewInt(1234)

	err = database.InsertCertificate(serialFake, "CN=Fake", subjectStr, time.Now(), time.Now().Add(time.Hour), []byte("fake-pem"))
	if err != nil {
		t.Fatalf("InsertCertificate failed: %v", err)
	}

	err = database.RevokeCertificate(fmt.Sprintf("%x", serialFake), "keyCompromise")
	if err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}

	crlBytes, err := GenerateCRL(caCert, key, 30)
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}
	if len(crlBytes) == 0 {
		t.Errorf("Empty CRL")
	}
}
