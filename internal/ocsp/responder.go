package ocsp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"micropki/internal/database"
	"micropki/internal/logger"

	xocsp "golang.org/x/crypto/ocsp"
)

type Responder struct {
	ResponderCert *x509.Certificate
	ResponderKey  crypto.Signer
	CACert        *x509.Certificate
	Cache         sync.Map // Added map for OCSP caching
}

func NewResponder(certPath, keyPath, caCertPath string) (*Responder, error) {
	// read certs and key
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	responderCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	blockCA, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(blockCA.Bytes)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	blockKey, _ := pem.Decode(keyPEM)

	privKey, err := x509.ParsePKCS8PrivateKey(blockKey.Bytes)
	if err != nil {
		return nil, err
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key is not a signer")
	}

	return &Responder{
		ResponderCert: responderCert,
		ResponderKey:  signer,
		CACert:        caCert,
	}, nil
}

func (r *Responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if req.Header.Get("Content-Type") != "application/ocsp-request" {
		http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	ocspReq, err := xocsp.ParseRequest(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Malformed request"))
		return
	}

	serialHex := fmt.Sprintf("%x", ocspReq.SerialNumber)

	// OCSP-7: Check Cache to avoid DB read
	type cacheEntry struct {
		status    int
		revTime   time.Time
		reason    int
		expiresAt time.Time
	}

	var status int
	var revTime time.Time
	var reason int

	if cached, ok := r.Cache.Load(serialHex); ok && time.Now().Before(cached.(cacheEntry).expiresAt) {
		entry := cached.(cacheEntry)
		status = entry.status
		revTime = entry.revTime
		reason = entry.reason
		logger.Info("[OCSP] Cache hit for serial=%s", serialHex)
	} else {
		record, err := database.GetCertificateBySerial(serialHex)
		if err != nil {
			status = xocsp.Unknown
		} else if record != nil {
			if record.Status == "revoked" {
				status = xocsp.Revoked
				if record.RevocationDate != nil {
					revTime, _ = time.Parse(time.RFC3339, *record.RevocationDate)
				}
				reason = 0 // default unspecified
			} else {
				status = xocsp.Good
			}
		} else {
			status = xocsp.Unknown
		}
		r.Cache.Store(serialHex, cacheEntry{
			status:    status,
			revTime:   revTime,
			reason:    reason,
			expiresAt: time.Now().Add(1 * time.Minute),
		})
	}

	// OCSP-4: Nonce Handling — parse nonce from raw request body via ASN.1
	// since x/crypto/ocsp.Request does not expose extensions
	var nonceExt *pkix.Extension
	nonceOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

	// ASN.1 structure: OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }
	// TBSRequest ::= SEQUENCE { ... requestExtensions [2] EXPLICIT Extensions OPTIONAL }
	type tbsRequest struct {
		Raw           asn1.RawContent
		Version       asn1.RawValue `asn1:"optional,explicit,default:0,tag:0"`
		RequestorName asn1.RawValue `asn1:"optional,explicit,tag:1"`
		RequestList   asn1.RawValue
		Extensions    []pkix.Extension `asn1:"optional,explicit,tag:2"`
	}
	type ocspRequest struct {
		TBSRequest tbsRequest
	}

	var rawReq ocspRequest
	if rest, err := asn1.Unmarshal(body, &rawReq); err == nil && len(rest) == 0 {
		for _, ext := range rawReq.TBSRequest.Extensions {
			if ext.Id.Equal(nonceOID) {
				nonceExt = &ext
				break
			}
		}
	}

	responseTemplate := xocsp.Response{
		Status:           status,
		SerialNumber:     ocspReq.SerialNumber,
		ThisUpdate:       time.Now(),
		NextUpdate:       time.Now().Add(5 * time.Minute),
		RevokedAt:        revTime,
		RevocationReason: reason,
		Certificate:      r.ResponderCert, // required by some clients
	}

	if nonceExt != nil {
		responseTemplate.ExtraExtensions = []pkix.Extension{*nonceExt}
	}

	responseDER, err := xocsp.CreateResponse(r.CACert, r.ResponderCert, responseTemplate, r.ResponderKey)
	if err != nil {
		logger.Error("Failed to create OCSP response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	logger.Info("[OCSP] Request Serial=%s Status=%v ProcessingTime=%dms", serialHex, status, time.Since(start).Milliseconds())

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(responseDER)
}
