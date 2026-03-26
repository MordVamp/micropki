package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"micropki/internal/audit"
	"micropki/internal/policy"
	internalcrypto "micropki/internal/crypto"
	"micropki/internal/database"
	"micropki/internal/logger"
	pkgserial "micropki/internal/serial"

	"github.com/spf13/cobra"
)

var issueOcspCmd = &cobra.Command{
	Use:   "issue-ocsp-cert",
	Short: "Issue an OCSP responder certificate",
	RunE:  runIssueOcsp,
}

var (
	ocspCACert       string
	ocspCAKey        string
	ocspCAPassFile   string
	ocspSubject      string
	ocspSANs         []string
	ocspOutDir       string
	ocspValidityDays int
	ocspLogFile      string
	ocspDbPath       string
)

func init() {
	flags := issueOcspCmd.Flags()
	flags.StringVar(&ocspCACert, "ca-cert", "", "Intermediate CA certificate (PEM)")
	flags.StringVar(&ocspCAKey, "ca-key", "", "Intermediate CA encrypted private key (PEM)")
	flags.StringVar(&ocspCAPassFile, "ca-pass-file", "", "Passphrase file for CA key")
	flags.StringVar(&ocspSubject, "subject", "", "Distinguished Name for the OCSP cert")
	flags.StringSliceVar(&ocspSANs, "san", []string{}, "Subject Alternative Name(s)")
	flags.StringVar(&ocspOutDir, "out-dir", "./pki/certs", "Output directory")
	flags.IntVar(&ocspValidityDays, "validity-days", 365, "Validity period in days")
	flags.StringVar(&ocspLogFile, "log-file", "", "Log file path")
	flags.StringVar(&ocspDbPath, "db-path", "./pki/micropki.db", "SQLite database path")

	cobra.MarkFlagRequired(flags, "ca-cert")
	cobra.MarkFlagRequired(flags, "ca-key")
	cobra.MarkFlagRequired(flags, "ca-pass-file")
	cobra.MarkFlagRequired(flags, "subject")

	CaCmd.AddCommand(issueOcspCmd)
}

func runIssueOcsp(cmd *cobra.Command, args []string) error {
	if err := logger.Init(ocspLogFile); err != nil {
		return err
	}
	defer logger.Close()

	if err := database.InitDB(ocspDbPath); err != nil {
		return fmt.Errorf("database init failed: %w", err)
	}

	logger.Info("Starting OCSP certificate issuance")

	caCertPEM, err := os.ReadFile(ocspCACert)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	caKeyPEM, err := os.ReadFile(ocspCAKey)
	if err != nil {
		return err
	}
	caPassphrase, err := os.ReadFile(ocspCAPassFile)
	if err != nil {
		return err
	}
	caPassphrase = []byte(strings.TrimRight(string(caPassphrase), "\r\n"))
	caPrivKey, err := internalcrypto.DecryptPrivateKey(caKeyPEM, caPassphrase)
	if err != nil {
		return err
	}

	subjectName, err := ParseDN(ocspSubject)
	if err != nil {
		return err
	}

	serial, err := pkgserial.GenerateUniqueSerial()
	if err != nil {
		return err
	}

	// Generate keys -> typically RSA 2048 for responder
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	pubKey := &priv.PublicKey

	// Policy enforce: Validity
	if err := policy.ValidateValidity(ocspValidityDays, "end-entity"); err != nil {
		logger.Error("Policy violation (Validity): %v", err)
		audit.LogEvent("AUDIT", "issue_ocsp", "failure", err.Error(), map[string]interface{}{"subject": subjectName.String()})
		return fmt.Errorf("policy violation: %w", err)
	}

	// Policy enforce: Key limits
	if err := policy.ValidateKey(pubKey, "end-entity"); err != nil {
		logger.Error("Policy violation (Key Size): %v", err)
		audit.LogEvent("AUDIT", "issue_ocsp", "failure", err.Error(), map[string]interface{}{"subject": subjectName.String()})
		return fmt.Errorf("policy violation: %w", err)
	}

	ski, _ := internalcrypto.ComputeSKI(pubKey)

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		Version:               3,
		SerialNumber:          serial,
		Subject:               subjectName,
		Issuer:                caCert.Subject,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, ocspValidityDays),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
	}

	for _, san := range ocspSANs {
		if strings.HasPrefix(san, "dns:") {
			tmpl.DNSNames = append(tmpl.DNSNames, strings.TrimPrefix(san, "dns:"))
		} else if strings.HasPrefix(san, "ip:") {
			// omitting IP parsing for brevity in sprint
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pubKey, caPrivKey)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if err := os.MkdirAll(ocspOutDir, 0700); err != nil {
		return err
	}

	baseName := "ocsp"
	certPath := filepath.Join(ocspOutDir, baseName+".cert.pem")
	keyPath := filepath.Join(ocspOutDir, baseName+".key.pem")

	os.WriteFile(certPath, certPEM, 0644)
	
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	os.WriteFile(keyPath, keyPEM, 0600)

	logger.Warning("OCSP private key is stored unencrypted at %s", keyPath)

	database.InsertCertificate(serial, tmpl.Subject.String(), caCert.Subject.String(), tmpl.NotBefore, tmpl.NotAfter, certPEM)

	h := crypto.SHA256.New()
	h.Write(certDER)
	fingerprint := fmt.Sprintf("%x", h.Sum(nil))
	audit.LogEvent("AUDIT", "issue_ocsp", "success", "Issued OCSP certificate", map[string]interface{}{
		"serial":  fmt.Sprintf("%x", serial),
		"subject": tmpl.Subject.String(),
	})
	audit.AppendCTLog(fmt.Sprintf("%x", serial), tmpl.Subject.String(), fingerprint, caCert.Subject.String())

	fmt.Printf("OCSP responder certificate issued:\nCert: %s\nKey:  %s\n", certPath, keyPath)
	return nil
}
