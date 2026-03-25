package ocsp

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"micropki/internal/database"
	"micropki/internal/logger"

	xocsp "golang.org/x/crypto/ocsp"
)

type Responder struct {
	ResponderCert *x509.Certificate
	ResponderKey  crypto.Signer
	CACert        *x509.Certificate
}

func NewResponder(certPath, keyPath, caCertPath string) (*Responder, error) {
	// read certs and key
	certPEM, err := os.ReadFile(certPath)
	if err != nil { return nil, err }
	block, _ := pem.Decode(certPEM)
	responderCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil { return nil, err }

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil { return nil, err }
	blockCA, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(blockCA.Bytes)
	if err != nil { return nil, err }

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil { return nil, err }
	blockKey, _ := pem.Decode(keyPEM)
	
	privKey, err := x509.ParsePKCS8PrivateKey(blockKey.Bytes)
	if err != nil { return nil, err }
	
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
	record, err := database.GetCertificateBySerial(serialHex)
	
	status := xocsp.Unknown
	var revTime time.Time
	var reason int

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

	responseTemplate := xocsp.Response{
		Status:       status,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(5 * time.Minute),
		RevokedAt:    revTime,
		RevocationReason: reason,
		Certificate:  r.ResponderCert, // required by some clients
	}

	// Nonce Handling is skipped as standard x/crypto/ocsp does not expose request extensions.

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
