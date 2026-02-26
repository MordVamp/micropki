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
