package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	internalcrypto "micropki/internal/crypto"
)

// GenerateRootCertificate creates a self-signed root CA certificate.
func GenerateRootCertificate(
	subject *pkix.Name,
	pub crypto.PublicKey,
	priv crypto.PrivateKey,
	validityDays int,
	serial *big.Int,
) ([]byte, error) {
	now := time.Now().UTC()
	template := &x509.Certificate{
		Version:      3,
		SerialNumber: serial,
		Subject:      *subject,
		Issuer:       *subject,
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, validityDays),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	ski, err := internalcrypto.ComputeSKI(pub)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId = ski
	template.AuthorityKeyId = ski
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return pem.EncodeToMemory(pemBlock), nil
}
