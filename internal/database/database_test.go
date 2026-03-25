package database

import (
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDatabaseOperations(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	err := InitDB(dbPath)
	if err != nil {
		if strings.Contains(err.Error(), "CGO_ENABLED=0") {
			t.Skipf("Skipping database test due to CGO_ENABLED=0 environment variables mapping a missing C compiler natively: %v", err)
		}
		t.Fatalf("InitDB failed: %v", err)
	}
	defer DB.Close()

	serial := big.NewInt(123456789)
	subject := "CN=Test Cert"
	issuer := "CN=Test CA"
	now := time.Now()

	err = InsertCertificate(serial, subject, issuer, now, now.Add(24*time.Hour), []byte("dummy-pem"))
	if err != nil {
		t.Fatalf("InsertCertificate failed: %v", err)
	}

	// hex of 123456789 is 75bcd15
	exists, err := CheckSerialExists("75bcd15")
	if err != nil || !exists {
		t.Fatalf("CheckSerialExists failed or returned false: %v", err)
	}

	// test insertion duplicate
	err = InsertCertificate(serial, subject, issuer, now, now.Add(24*time.Hour), []byte("dummy-pem"))
	if err == nil {
		t.Fatalf("Expected constraint violation on duplicate serial, got nil")
	}

	rec, err := GetCertificateBySerial("75bcd15")
	if err != nil || rec == nil {
		t.Fatalf("GetCertificateBySerial failed: %v", err)
	}
	if rec.Subject != subject {
		t.Errorf("Expected subject %s, got %s", subject, rec.Subject)
	}

	list, err := ListCertificates("valid")
	if err != nil {
		t.Fatalf("ListCertificates failed: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("Expected 1 cert in list, got %d", len(list))
	}
}
