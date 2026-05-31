package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCrypto(t *testing.T) {
	// GenerateRSAKey
	rsaKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048 bits, got %d", rsaKey.N.BitLen())
	}
	
	// GenerateECCKey
	eccKey, err := GenerateECCKey()
	if err != nil {
		t.Fatalf("GenerateECCKey: %v", err)
	}
	if eccKey.Curve != elliptic.P384() {
		t.Errorf("Expected P-384 curve")
	}
	
	// Zeroize
	buf := []byte{1, 2, 3, 4}
	Zeroize(buf)
	if !bytes.Equal(buf, []byte{0, 0, 0, 0}) {
		t.Errorf("Zeroize failed")
	}
	
	// Encrypt & Decrypt RSA
	passphrase := []byte("secret")
	encryptedPEM, err := EncryptPrivateKey(rsaKey, passphrase)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	decryptedKey, err := DecryptPrivateKey(encryptedPEM, passphrase)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}
	if _, ok := decryptedKey.(*rsa.PrivateKey); !ok {
		t.Errorf("Expected RSA private key")
	}
	
	// Encrypt & Decrypt ECC
	eccEncrypted, err := EncryptPrivateKey(eccKey, passphrase)
	if err != nil {
		t.Fatalf("EncryptPrivateKey (ECC): %v", err)
	}
	eccDecrypted, err := DecryptPrivateKey(eccEncrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptPrivateKey (ECC): %v", err)
	}
	if _, ok := eccDecrypted.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Expected ECC private key")
	}

	// ComputeSKI
	ski, err := ComputeSKI(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSKI: %v", err)
	}
	if len(ski) != 20 {
		t.Errorf("Expected SKI length 20, got %d", len(ski))
	}
	
	// WritePEMFile
	tmpFile := filepath.Join(t.TempDir(), "test.pem")
	block := &pem.Block{Type: "TEST", Bytes: []byte("test")}
	err = WritePEMFile(tmpFile, block, 0644)
	if err != nil {
		t.Fatalf("WritePEMFile: %v", err)
	}
	if _, err := os.Stat(tmpFile); err != nil {
		t.Errorf("File not created")
	}
}
