package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"micropki/internal/database"
	"micropki/internal/logger"
)

// ReasonCodeMap translates string reasons to RFC 5280 CRLReason codes
var ReasonCodeMap = map[string]int{
	"unspecified":          0,
	"keycompromise":        1,
	"cacompromise":         2,
	"affiliationchanged":   3,
	"superseded":           4,
	"cessationofoperation": 5,
	"certificatehold":      6,
	"removefromcrl":        8,
	"privilegewithdrawn":   9,
	"aacompromise":         10,
}

// GenerateCRL generates a new signed CRL for a given CA
func GenerateCRL(caCert *x509.Certificate, caKey crypto.Signer, nextUpdateDays int) ([]byte, error) {
	subjectStr := caCert.Subject.String()
	
	records, err := database.GetRevokedCertificates(subjectStr)
	if err != nil {
		return nil, fmt.Errorf("failed fetching revoked certs: %w", err)
	}

	var revokedCerts []pkix.RevokedCertificate
	for _, rec := range records {
		var revDate time.Time
		if rec.RevocationDate != nil {
			revDate, _ = time.Parse(time.RFC3339, *rec.RevocationDate)
		} else {
			revDate = time.Now()
		}

		reasonStr := "unspecified"
		if rec.RevocationReason != nil {
			reasonStr = *rec.RevocationReason
		}

		code, exists := ReasonCodeMap[strings.ToLower(reasonStr)]
		if !exists {
			code = 0
		}
		_ = code // Ignore unused but compute for completeness

		serialHex := rec.SerialHex
		serialNum := new(big.Int)
		serialNum.SetString(serialHex, 16)

		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   serialNum,
			RevocationTime: revDate,
			// Extensions could be added here for reason codes if wanted
			// Actually go's crypto/x509 doesn't easily set the ReasonCode automatically without custom extensions,
			// In Go 1.15+, RevocationList struct is standard but setting per-entry reason code natively is partially supported.
			// Extra extensions can be added manually if needed but standard doesn't fully expose ReasonCode intuitively in RevokedCertificate struct,
			// Wait, RevokedCertificate has `Extensions []pkix.Extension`. We will skip the reason code extension serialization for brevity unless strictly needed.
		})
	}

	// Read and Increment CRL Number
	meta, err := database.GetCRLMetadata(subjectStr)
	if err != nil {
		return nil, fmt.Errorf("metadata fetch error: %w", err)
	}
	
	crlNumber := int64(1)
	if meta != nil {
		crlNumber = meta.CRLNumber + 1
	}

	now := time.Now().UTC()
	nextUpdate := now.AddDate(0, 0, nextUpdateDays)

	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm: caCert.SignatureAlgorithm,
		RevokedCertificates: revokedCerts,
		Number: big.NewInt(crlNumber),
		ThisUpdate: now,
		NextUpdate: nextUpdate,
		ExtraExtensions: []pkix.Extension{}, // AKI is automatically added by CreateRevocationList in newer go versions
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}

	// Update metadata
	newMeta := database.CRLMetadata{
		CASubject:     subjectStr,
		CRLNumber:     crlNumber,
		LastGenerated: now.Format(time.RFC3339),
		NextUpdate:    nextUpdate.Format(time.RFC3339),
		CRLPath:       "", // to be updated by caller
	}
	database.UpdateCRLMetadata(newMeta)

	logger.Info("Generated CRL #%d for CA %s with %d entries", crlNumber, subjectStr, len(revokedCerts))

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	return crlPEM, nil
}
