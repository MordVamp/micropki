package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateRSAKey creates a new RSA private key of the given size.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// GenerateECCKey creates a new ECDSA private key on the P-384 curve.
func GenerateECCKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// EncryptPrivateKey encrypts a private key with the given passphrase using PKCS#8 (AES-256-CBC + PBKDF2).
// This matches the "BestAvailableEncryption" style used in Python's cryptography.
func EncryptPrivateKey(key crypto.PrivateKey, passphrase []byte) ([]byte, error) {
	// Marshal the private key to PKCS#8 DER
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Encrypt the DER using PKCS#8 with AES-256-CBC and PBKDF2
	encryptedDer, err := x509.EncryptPEMBlock(rand.Reader, "ENCRYPTED PRIVATE KEY", der, passphrase, x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	return pem.EncodeToMemory(encryptedDer), nil
}

// WritePEMFile writes a PEM block to a file with the given permissions.
func WritePEMFile(filename string, pemBlock *pem.Block, perm os.FileMode) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, pemBlock)
}

// ComputeSKI computes the Subject Key Identifier as the SHA-1 hash of the public key bytes.
func ComputeSKI(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	// SHA-1 hash as per RFC 5280
	hash := sha1.Sum(der)
	return hash[:], nil
}
