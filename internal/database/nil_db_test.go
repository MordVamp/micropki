package database

import (
	"math/big"
	"testing"
	"time"
)

func TestNilDBPaths(t *testing.T) {
	// Ensure DB is nil
	originalDB := DB
	DB = nil
	defer func() { DB = originalDB }()

	if err := InsertCertificate(big.NewInt(1), "subj", "issuer", time.Now(), time.Now(), nil); err == nil {
		t.Error("expected error when DB is nil in InsertCertificate")
	}

	if _, err := GetCertificateBySerial("abc"); err == nil {
		t.Error("expected error when DB is nil in GetCertificateBySerial")
	}

	if _, err := ListCertificates("valid"); err == nil {
		t.Error("expected error when DB is nil in ListCertificates")
	}

	if _, err := CheckSerialExists("abc"); err == nil {
		t.Error("expected error when DB is nil in CheckSerialExists")
	}

	if err := RevokeCertificate("abc", "unspecified"); err == nil {
		t.Error("expected error when DB is nil in RevokeCertificate")
	}

	if _, err := GetRevokedCertificates("issuer"); err == nil {
		t.Error("expected error when DB is nil in GetRevokedCertificates")
	}

	if _, err := GetCRLMetadata("subj"); err == nil {
		t.Error("expected error when DB is nil in GetCRLMetadata")
	}

	if err := UpdateCRLMetadata(CRLMetadata{}); err == nil {
		t.Error("expected error when DB is nil in UpdateCRLMetadata")
	}

	if err := MarkKeyCompromised("hash", "serial", "date", "reason"); err == nil {
		t.Error("expected error when DB is nil in MarkKeyCompromised")
	}

	if _, err := IsKeyCompromised("hash"); err == nil {
		t.Error("expected error when DB is nil in IsKeyCompromised")
	}
}
