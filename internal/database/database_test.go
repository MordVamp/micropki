package database

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	if err := InitDB(dbPath); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	t.Cleanup(func() { os.Remove(dbPath) })
	return dbPath
}

func insertTestCert(t *testing.T, serialHex string, subject, issuer string) {
	t.Helper()
	serial := new(big.Int)
	serial.SetString(serialHex, 16)
	err := InsertCertificate(serial, subject, issuer,
		time.Now(), time.Now().AddDate(1, 0, 0), []byte("FAKEPEM"))
	if err != nil {
		t.Fatalf("InsertCertificate failed: %v", err)
	}
}

func TestRevokeCertificate(t *testing.T) {
	setupTestDB(t)
	insertTestCert(t, "aabbcc", "CN=Test", "CN=Issuer")

	// Revoke it
	if err := RevokeCertificate("aabbcc", "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}

	// Verify status changed
	rec, err := GetCertificateBySerial("aabbcc")
	if err != nil {
		t.Fatalf("GetCertificateBySerial failed: %v", err)
	}
	if rec == nil {
		t.Fatal("expected record, got nil")
	}
	if rec.Status != "revoked" {
		t.Errorf("expected status=revoked, got %s", rec.Status)
	}
	if rec.RevocationReason == nil || *rec.RevocationReason != "keyCompromise" {
		t.Errorf("expected reason=keyCompromise, got %v", rec.RevocationReason)
	}
	if rec.RevocationDate == nil {
		t.Error("expected revocation_date to be set")
	}
}

func TestRevokeCertificate_NotFound(t *testing.T) {
	setupTestDB(t)
	err := RevokeCertificate("deadbeef", "unspecified")
	if err == nil {
		t.Error("expected error for non-existent serial, got nil")
	}
}

func TestRevokeCertificate_AlreadyRevoked(t *testing.T) {
	setupTestDB(t)
	insertTestCert(t, "112233", "CN=Double", "CN=Issuer")
	_ = RevokeCertificate("112233", "unspecified")

	// Second revoke should fail (already revoked, status != 'valid')
	err := RevokeCertificate("112233", "superseded")
	if err == nil {
		t.Error("expected error revoking already-revoked cert, got nil")
	}
}

func TestGetRevokedCertificates(t *testing.T) {
	setupTestDB(t)
	insertTestCert(t, "aa11", "CN=Alpha", "CN=MyCA")
	insertTestCert(t, "bb22", "CN=Beta", "CN=MyCA")
	insertTestCert(t, "cc33", "CN=Gamma", "CN=OtherCA")

	_ = RevokeCertificate("aa11", "keyCompromise")
	_ = RevokeCertificate("bb22", "superseded")

	records, err := GetRevokedCertificates("CN=MyCA")
	if err != nil {
		t.Fatalf("GetRevokedCertificates failed: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("expected 2 revoked certs for CN=MyCA, got %d", len(records))
	}

	// OtherCA should yield 0
	records2, err := GetRevokedCertificates("CN=OtherCA")
	if err != nil {
		t.Fatalf("GetRevokedCertificates (OtherCA) failed: %v", err)
	}
	if len(records2) != 0 {
		t.Errorf("expected 0 revoked certs for OtherCA, got %d", len(records2))
	}
}

func TestCRLMetadata_InsertAndUpdate(t *testing.T) {
	setupTestDB(t)

	// Initially nil
	meta, err := GetCRLMetadata("CN=TestCA")
	if err != nil {
		t.Fatalf("GetCRLMetadata (empty) failed: %v", err)
	}
	if meta != nil {
		t.Error("expected nil metadata for fresh CA")
	}

	// Insert
	now := time.Now().UTC()
	if err := UpdateCRLMetadata(CRLMetadata{
		CASubject:     "CN=TestCA",
		CRLNumber:     1,
		LastGenerated: now.Format(time.RFC3339),
		NextUpdate:    now.AddDate(0, 0, 7).Format(time.RFC3339),
		CRLPath:       "./crl/test.crl.pem",
	}); err != nil {
		t.Fatalf("UpdateCRLMetadata (insert) failed: %v", err)
	}

	meta, err = GetCRLMetadata("CN=TestCA")
	if err != nil {
		t.Fatalf("GetCRLMetadata (after insert) failed: %v", err)
	}
	if meta == nil {
		t.Fatal("expected metadata after insert, got nil")
	}
	if meta.CRLNumber != 1 {
		t.Errorf("expected CRLNumber=1, got %d", meta.CRLNumber)
	}

	// Update (second call to UpdateCRLMetadata should UPDATE, not INSERT)
	if err := UpdateCRLMetadata(CRLMetadata{
		CASubject:     "CN=TestCA",
		CRLNumber:     2,
		LastGenerated: now.Format(time.RFC3339),
		NextUpdate:    now.AddDate(0, 0, 14).Format(time.RFC3339),
		CRLPath:       "./crl/test2.crl.pem",
	}); err != nil {
		t.Fatalf("UpdateCRLMetadata (update) failed: %v", err)
	}

	meta, err = GetCRLMetadata("CN=TestCA")
	if err != nil {
		t.Fatalf("GetCRLMetadata (after update) failed: %v", err)
	}
	if meta.CRLNumber != 2 {
		t.Errorf("expected CRLNumber=2 after update, got %d", meta.CRLNumber)
	}
}

func TestMarkKeyCompromised_AndIsKeyCompromised(t *testing.T) {
	setupTestDB(t)
	insertTestCert(t, "feedface", "CN=Victim", "CN=Issuer")

	hash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	now := time.Now().UTC().Format(time.RFC3339)

	// Not compromised initially
	compromised, err := IsKeyCompromised(hash)
	if err != nil {
		t.Fatalf("IsKeyCompromised (initial) failed: %v", err)
	}
	if compromised {
		t.Error("expected not compromised initially")
	}

	// Mark as compromised
	if err := MarkKeyCompromised(hash, "feedface", now, "keyCompromise"); err != nil {
		t.Fatalf("MarkKeyCompromised failed: %v", err)
	}

	// Now should be compromised
	compromised, err = IsKeyCompromised(hash)
	if err != nil {
		t.Fatalf("IsKeyCompromised (after mark) failed: %v", err)
	}
	if !compromised {
		t.Error("expected key to be marked compromised")
	}

	// Case insensitivity
	compromised, err = IsKeyCompromised(strings.ToUpper(hash))
	if err != nil {
		t.Fatalf("IsKeyCompromised (uppercase) failed: %v", err)
	}
	if !compromised {
		t.Error("expected case-insensitive match for compromised key")
	}
}

func TestMarkKeyCompromised_DuplicateIgnored(t *testing.T) {
	setupTestDB(t)
	insertTestCert(t, "cafe1234", "CN=Dup", "CN=Issuer")

	hash := "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
	now := time.Now().UTC().Format(time.RFC3339)

	// First insert
	if err := MarkKeyCompromised(hash, "cafe1234", now, "keyCompromise"); err != nil {
		t.Fatalf("first MarkKeyCompromised failed: %v", err)
	}
	// Second insert should be silently ignored (ON CONFLICT DO NOTHING)
	if err := MarkKeyCompromised(hash, "cafe1234", now, "caCompromise"); err != nil {
		t.Fatalf("second MarkKeyCompromised (duplicate) failed: %v", err)
	}
}

func TestCreateDBIfNotExists(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "new.db")
	if err := CreateDBIfNotExists(dbPath); err != nil {
		t.Fatalf("CreateDBIfNotExists failed: %v", err)
	}
}

func TestListCertificates_FilterByStatus(t *testing.T) {
	setupTestDB(t)
	insertTestCert(t, "11aa", "CN=A", "CN=CA")
	insertTestCert(t, "22bb", "CN=B", "CN=CA")
	_ = RevokeCertificate("22bb", "unspecified")

	all, err := ListCertificates("")
	if err != nil {
		t.Fatalf("ListCertificates (all) failed: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 total certs, got %d", len(all))
	}

	valid, err := ListCertificates("valid")
	if err != nil {
		t.Fatalf("ListCertificates (valid) failed: %v", err)
	}
	if len(valid) != 1 {
		t.Errorf("expected 1 valid cert, got %d", len(valid))
	}

	revoked, err := ListCertificates("revoked")
	if err != nil {
		t.Fatalf("ListCertificates (revoked) failed: %v", err)
	}
	if len(revoked) != 1 {
		t.Errorf("expected 1 revoked cert, got %d", len(revoked))
	}
}

func TestCheckSerialExists(t *testing.T) {
	setupTestDB(t)
	insertTestCert(t, "123abc", "CN=Check", "CN=Issuer")

	exists, err := CheckSerialExists("123abc")
	if err != nil {
		t.Fatalf("CheckSerialExists (exists) failed: %v", err)
	}
	if !exists {
		t.Error("expected serial to exist")
	}

	exists, err = CheckSerialExists("ffffff")
	if err != nil {
		t.Fatalf("CheckSerialExists (not found) failed: %v", err)
	}
	if exists {
		t.Error("expected serial to not exist")
	}
}
