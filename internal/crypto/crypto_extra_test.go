package crypto

import (
	"crypto/rsa"
	"testing"
)

func TestCryptoErrorPaths(t *testing.T) {
	// EncryptPrivateKey with unsupported key type
	_, err := EncryptPrivateKey("not a key", []byte("pass"))
	if err == nil {
		t.Error("Expected error encrypting unsupported key")
	}

	// DecryptPrivateKey with invalid PEM
	_, err = DecryptPrivateKey([]byte("invalid pem"), []byte("pass"))
	if err == nil {
		t.Error("Expected error decrypting invalid PEM")
	}

	// DecryptPrivateKey with invalid passphrase
	rsaKey, _ := GenerateRSAKey(2048)
	encryptedPEM, _ := EncryptPrivateKey(rsaKey, []byte("pass"))
	_, err = DecryptPrivateKey(encryptedPEM, []byte("wrong_pass"))
	if err == nil {
		t.Error("Expected error decrypting with wrong passphrase")
	}

	// ComputeSKI with unsupported key type
	_, err = ComputeSKI("not a key")
	if err == nil {
		t.Error("Expected error computing SKI of unsupported key")
	}

	// ComputeSKI of RSA key pointer vs value
	// value should fail because we expect pointer
	var val rsa.PublicKey
	_, err = ComputeSKI(val)
	if err == nil {
		t.Error("Expected error computing SKI of non-pointer key")
	}
}
