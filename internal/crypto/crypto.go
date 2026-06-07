package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// GenerateRSAKey creates a new RSA private key of the given size.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// GenerateECCKey creates a new ECDSA private key on the P-384 curve.
func GenerateECCKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// Zeroize clears the contents of a byte slice to prevent secrets from lingering in memory.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// EncryptPrivateKey encrypts a private key with the given passphrase using ChaCha20-Poly1305 and PBKDF2.
func EncryptPrivateKey(key crypto.PrivateKey, passphrase []byte) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	defer Zeroize(der)

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	keyDerivation := pbkdf2.Key(passphrase, salt, 100000, 32, sha256.New)
	defer Zeroize(keyDerivation)

	aead, err := chacha20poly1305.New(keyDerivation)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, der, nil)

	// Format for PEM: salt + nonce + ciphertext
	payload := append(salt, nonce...)
	payload = append(payload, ciphertext...)

	block := &pem.Block{
		Type:  "CHACHA20 ENCRYPTED PRIVATE KEY",
		Bytes: payload,
	}

	return pem.EncodeToMemory(block), nil
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
	hash := sha1.Sum(der)
	return hash[:], nil
}

// DecryptPrivateKey decrypts an encrypted PEM private key using the passphrase.
func DecryptPrivateKey(pemData []byte, passphrase []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM")
	}

	var der []byte
	var err error

	switch block.Type {
	case "CHACHA20 ENCRYPTED PRIVATE KEY":
		if len(block.Bytes) < 16+12 { // salt (16) + nonce (12)
			return nil, fmt.Errorf("invalid payload length")
		}
		salt := block.Bytes[:16]
		nonce := block.Bytes[16:28]
		ciphertext := block.Bytes[28:]

		keyDerivation := pbkdf2.Key(passphrase, salt, 100000, 32, sha256.New)
		defer Zeroize(keyDerivation)

		aead, err := chacha20poly1305.New(keyDerivation)
		if err != nil {
			return nil, err
		}

		der, err = aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt chacha20 private key: %w", err)
		}
		defer Zeroize(der)
		return x509.ParsePKCS8PrivateKey(der)
	case "ENCRYPTED PRIVATE KEY":
		der, err = x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt PKCS#8 key: %w", err)
		}
		defer Zeroize(der)
		return x509.ParsePKCS8PrivateKey(der)
	case "RSA PRIVATE KEY":
		der, err = x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt RSA key: %w", err)
		}
		defer Zeroize(der)
		return x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		der, err = x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt EC key: %w", err)
		}
		defer Zeroize(der)
		return x509.ParseECPrivateKey(der)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}
