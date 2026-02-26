package policy

import (
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
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
