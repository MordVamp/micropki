package policy

import (
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
	"crypto"
	"crypto/rsa"
	"crypto/ecdsa"
	"net"
	"net/url"
)

// Write creates a policy.txt file with the given CA information.
func Write(path string, name *pkix.Name, serial *big.Int, validityDays int, keyType string, keySize int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now().UTC()
	notBefore := now
	notAfter := now.AddDate(0, 0, validityDays)

	_, err = fmt.Fprintf(f, `Certificate Policy Document

CA Name: %s
Serial Number: %X
Validity:
  Not Before: %s
  Not After : %s
Key Algorithm: %s-%d
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: %s
`,
		name.String(),
		serial,
		notBefore.Format(time.RFC3339),
		notAfter.Format(time.RFC3339),
		strings.ToUpper(keyType), keySize,
		now.Format(time.RFC3339),
	)
	return err
}

// AppendIntermediate appends information about an Intermediate CA to the policy file.
func AppendIntermediate(path string, name *pkix.Name, serial *big.Int, validityDays int, keyType string, keySize int, pathlen int, issuer *pkix.Name) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now().UTC()
	notBefore := now
	notAfter := now.AddDate(0, 0, validityDays)

	_, err = fmt.Fprintf(f, `
Intermediate CA
---------------
Subject: %s
Serial Number: %X
Issuer: %s
Validity:
  Not Before: %s
  Not After : %s
Key Algorithm: %s-%d
Path Length Constraint: %d
Issuance Date: %s
`,
		name.String(),
		serial,
		issuer.String(),
		notBefore.Format(time.RFC3339),
		notAfter.Format(time.RFC3339),
		strings.ToUpper(keyType), keySize,
		pathlen,
		now.Format(time.RFC3339),
	)
	return err
}

// ValidateKey size rules
func ValidateKey(pub crypto.PublicKey, role string) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		size := k.Size() * 8
		if role == "root" && size < 4096 {
			return fmt.Errorf("root RSA key must be >= 4096 bits")
		}
		if role == "intermediate" && size < 3072 {
			return fmt.Errorf("intermediate RSA key must be >= 3072 bits")
		}
		if role == "end-entity" && size < 2048 {
			return fmt.Errorf("RSA key must be >= 2048 bits")
		}
	case *ecdsa.PublicKey:
		size := k.Params().BitSize
		if (role == "root" || role == "intermediate") && size < 384 {
			return fmt.Errorf("CA ECC key must be >= P-384")
		}
		if role == "end-entity" && size < 256 {
			return fmt.Errorf("ECC key must be >= P-256")
		}
	default:
		return fmt.Errorf("unsupported public key type")
	}
	return nil
}

// ValidateValidity period rules
func ValidateValidity(days int, role string) error {
	if role == "root" && days > 3650 {
		return fmt.Errorf("root validity exceeds max 3650 days")
	}
	if role == "intermediate" && days > 1825 {
		return fmt.Errorf("intermediate validity exceeds max 1825 days")
	}
	if role == "end-entity" && days > 365 {
		return fmt.Errorf("end-entity validity exceeds max 365 days")
	}
	return nil
}

// ValidateSANs type rules
func ValidateSANs(dnsNames, emails []string, ips []net.IP, uris []*url.URL, template string) error {
	for _, dns := range dnsNames {
		if strings.HasPrefix(dns, "*.") {
			return fmt.Errorf("wildcard certificates are prohibited by policy")
		}
	}

	switch template {
	case "server":
		if len(emails) > 0 || len(uris) > 0 {
			return fmt.Errorf("server template prohibits email and URI SANs")
		}
	case "client":
		if len(ips) > 0 || len(uris) > 0 {
			return fmt.Errorf("client template prohibits IP and URI SANs")
		}
	case "code_signing":
		if len(ips) > 0 || len(emails) > 0 {
			return fmt.Errorf("code_signing template prohibits IP and email SANs")
		}
	}
	return nil
}
