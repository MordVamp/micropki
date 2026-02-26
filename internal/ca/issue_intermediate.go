package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	internalcrypto "micropki/internal/crypto"
	"micropki/internal/logger"
	"micropki/internal/policy"

	"github.com/spf13/cobra"
)

var _ = pkix.Name{} // ensure pkix import is used

var issueIntermediateCmd = &cobra.Command{
	Use:   "issue-intermediate",
	Short: "Issue an Intermediate CA certificate signed by the Root CA",
	Long:  `Generate a CSR for an Intermediate CA and have it signed by the Root CA.`,
	RunE:  runIssueIntermediate,
}

// Flags for issue-intermediate
var (
	interRootCert       string
	interRootKey        string
	interRootPassFile   string
	interSubject        string
	interKeyType        string
	interKeySize        int
	interPassphraseFile string
	interOutDir         string
	interValidityDays   int
	interPathLen        int
	interLogFile        string
)

func init() {
	flags := issueIntermediateCmd.Flags()
	flags.StringVar(&interRootCert, "root-cert", "", "Path to Root CA certificate (PEM)")
	flags.StringVar(&interRootKey, "root-key", "", "Path to Root CA encrypted private key (PEM)")
	flags.StringVar(&interRootPassFile, "root-pass-file", "", "File containing passphrase for Root CA key")
	flags.StringVar(&interSubject, "subject", "", "Distinguished Name for Intermediate CA")
	flags.StringVar(&interKeyType, "key-type", "rsa", "Key type: rsa or ecc")
	flags.IntVar(&interKeySize, "key-size", 4096, "Key size in bits (4096 for RSA, 384 for ECC)")
	flags.StringVar(&interPassphraseFile, "passphrase-file", "", "Passphrase file for Intermediate CA private key")
	flags.StringVar(&interOutDir, "out-dir", "./pki", "Output directory")
	flags.IntVar(&interValidityDays, "validity-days", 1825, "Validity period in days (default 5 years)")
	flags.IntVar(&interPathLen, "pathlen", 0, "Path length constraint (default 0)")
	flags.StringVar(&interLogFile, "log-file", "", "Log file path (default: stderr)")

	cobra.MarkFlagRequired(flags, "root-cert")
	cobra.MarkFlagRequired(flags, "root-key")
	cobra.MarkFlagRequired(flags, "root-pass-file")
	cobra.MarkFlagRequired(flags, "subject")
	cobra.MarkFlagRequired(flags, "passphrase-file")
}

func runIssueIntermediate(cmd *cobra.Command, args []string) error {
	if err := logger.Init(interLogFile); err != nil {
		return fmt.Errorf("failed to init logger: %w", err)
	}
	defer logger.Close()

	logger.Info("Starting Intermediate CA issuance")

	// Validate arguments
	if err := validateIssueIntermediateArgs(); err != nil {
		logger.Error("Validation failed: %v", err)
		return err
	}

	// Load Root CA certificate
	rootCertPEM, err := os.ReadFile(interRootCert)
	if err != nil {
		logger.Error("Failed to read root certificate: %v", err)
		return fmt.Errorf("cannot read root certificate: %w", err)
	}
	block, _ := pem.Decode(rootCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		logger.Error("Invalid root certificate PEM")
		return fmt.Errorf("invalid root certificate")
	}
	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Error("Failed to parse root certificate: %v", err)
		return fmt.Errorf("invalid root certificate: %w", err)
	}
	logger.Info("Root CA certificate loaded: %s", rootCert.Subject)

	// Load Root CA private key (encrypted)
	rootKeyPEM, err := os.ReadFile(interRootKey)
	if err != nil {
		logger.Error("Failed to read root key: %v", err)
		return fmt.Errorf("cannot read root key: %w", err)
	}
	rootPassphrase, err := os.ReadFile(interRootPassFile)
	if err != nil {
		logger.Error("Failed to read root passphrase file: %v", err)
		return fmt.Errorf("cannot read root passphrase: %w", err)
	}
	rootPassphrase = []byte(strings.TrimRight(string(rootPassphrase), "\r\n"))
	rootPrivKey, err := internalcrypto.DecryptPrivateKey(rootKeyPEM, rootPassphrase)
	if err != nil {
		logger.Error("Failed to decrypt root private key: %v", err)
		return fmt.Errorf("root key decryption failed: %w", err)
	}
	logger.Info("Root CA private key loaded")

	// Generate Intermediate key pair
	logger.Info("Generating %s key (%d bits) for Intermediate CA", interKeyType, interKeySize)
	var interPrivKey crypto.PrivateKey
	var interPubKey crypto.PublicKey
	switch interKeyType {
	case "rsa":
		rsaKey, err := internalcrypto.GenerateRSAKey(interKeySize)
		if err != nil {
			logger.Error("RSA key generation failed: %v", err)
			return err
		}
		interPrivKey = rsaKey
		interPubKey = &rsaKey.PublicKey
	case "ecc":
		eccKey, err := internalcrypto.GenerateECCKey()
		if err != nil {
			logger.Error("ECC key generation failed: %v", err)
			return err
		}
		interPrivKey = eccKey
		interPubKey = &eccKey.PublicKey
	default:
		return fmt.Errorf("unsupported key type")
	}
	logger.Info("Intermediate key generation completed")

	// Parse subject DN
	subjectName, err := ParseDN(interSubject)
	if err != nil {
		logger.Error("Invalid subject DN: %v", err)
		return fmt.Errorf("invalid subject: %w", err)
	}

	// Generate CSR for Intermediate CA
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: subjectName,
		// BasicConstraints can be included in CSR but is not mandatory; we'll rely on template during signing.
		// Optionally we could add extensions to CSR.
	}, interPrivKey)
	if err != nil {
		logger.Error("Failed to create CSR: %v", err)
		return fmt.Errorf("CSR creation failed: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		logger.Error("Failed to parse CSR: %v", err)
		return fmt.Errorf("CSR parsing failed: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		logger.Error("CSR signature verification failed: %v", err)
		return fmt.Errorf("CSR signature invalid: %w", err)
	}
	logger.Info("Intermediate CSR created and verified")

	// Generate serial number for intermediate certificate
	serialBytes := make([]byte, 20)
	if _, err := rand.Read(serialBytes); err != nil {
		logger.Error("Failed to generate serial number: %v", err)
		return fmt.Errorf("serial generation failed: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)
	logger.Info("Serial number generated: %x", serial)

	// Compute SKI for intermediate public key
	ski, err := internalcrypto.ComputeSKI(interPubKey)
	if err != nil {
		logger.Error("Failed to compute SKI: %v", err)
		return fmt.Errorf("SKI computation failed: %w", err)
	}

	// Build certificate template for Intermediate CA
	now := time.Now().UTC()
	template := &x509.Certificate{
		Version:      3,
		SerialNumber: serial,
		Subject:      csr.Subject, // Use subject from CSR (which we built)
		Issuer:       rootCert.Subject,
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, interValidityDays),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            interPathLen,
		MaxPathLenZero:        interPathLen == 0, // important to set zero correctly

		SubjectKeyId: ski,

		// Extensions can be added here, but we already set KeyUsage and BasicConstraints.
		// The AuthorityKeyId will be set by CreateCertificate using the issuer's SubjectKeyId.
	}

	// Sign the certificate with Root CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, csr.PublicKey, rootPrivKey)
	if err != nil {
		logger.Error("Failed to sign intermediate certificate: %v", err)
		return fmt.Errorf("certificate signing failed: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	logger.Info("Intermediate certificate signed")

	// Prepare directories
	privateDir := filepath.Join(interOutDir, "private")
	certsDir := filepath.Join(interOutDir, "certs")
	csrDir := filepath.Join(interOutDir, "csrs") // optional
	for _, dir := range []string{privateDir, certsDir, csrDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			logger.Error("Failed to create directory %s: %v", dir, err)
			return fmt.Errorf("cannot create directory %s: %w", dir, err)
		}
	}

	// Encrypt and save intermediate private key
	interPassphrase, err := os.ReadFile(interPassphraseFile)
	if err != nil {
		logger.Error("Failed to read intermediate passphrase file: %v", err)
		return fmt.Errorf("cannot read passphrase file: %w", err)
	}
	interPassphrase = []byte(strings.TrimRight(string(interPassphrase), "\r\n"))
	encryptedKey, err := internalcrypto.EncryptPrivateKey(interPrivKey, interPassphrase)
	if err != nil {
		logger.Error("Failed to encrypt intermediate private key: %v", err)
		return fmt.Errorf("key encryption failed: %w", err)
	}
	keyPath := filepath.Join(privateDir, "intermediate.key.pem")
	if err := os.WriteFile(keyPath, encryptedKey, 0600); err != nil {
		logger.Error("Failed to write intermediate private key: %v", err)
		return fmt.Errorf("cannot write private key: %w", err)
	}
	logger.Info("Intermediate private key saved to %s", keyPath)

	// Save intermediate certificate
	certPath := filepath.Join(certsDir, "intermediate.cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		logger.Error("Failed to write intermediate certificate: %v", err)
		return fmt.Errorf("cannot write certificate: %w", err)
	}
	logger.Info("Intermediate certificate saved to %s", certPath)

	// Optionally save CSR for audit
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrPath := filepath.Join(csrDir, "intermediate.csr.pem")
	if err := os.WriteFile(csrPath, csrPEM, 0644); err != nil {
		logger.Warning("Failed to write CSR: %v", err) // non-critical
	} else {
		logger.Info("CSR saved to %s", csrPath)
	}

	// Update policy document with intermediate info
	policyPath := filepath.Join(interOutDir, "policy.txt")
	// We need to append, not overwrite. We'll create a helper in policy package.
	if err := policy.AppendIntermediate(policyPath, &subjectName, serial, interValidityDays, interKeyType, interKeySize, interPathLen, &rootCert.Subject); err != nil {
		logger.Error("Failed to update policy document: %v", err)
		return fmt.Errorf("policy update failed: %w", err)
	}
	logger.Info("Policy document updated")

	logger.Info("Intermediate CA issuance completed successfully")
	fmt.Printf("Intermediate CA successfully created in %s\n", interOutDir)
	return nil
}

func validateIssueIntermediateArgs() error {
	// Similar validation as init, plus check that root files exist
	if interSubject == "" {
		return fmt.Errorf("subject cannot be empty")
	}
	if interKeyType != "rsa" && interKeyType != "ecc" {
		return fmt.Errorf("key-type must be 'rsa' or 'ecc'")
	}
	if interKeyType == "rsa" && interKeySize != 4096 {
		return fmt.Errorf("RSA key size must be 4096")
	}
	if interKeyType == "ecc" && interKeySize != 384 {
		return fmt.Errorf("ECC key size must be 384")
	}
	if interValidityDays <= 0 {
		return fmt.Errorf("validity-days must be positive")
	}
	if interPathLen < 0 {
		return fmt.Errorf("pathlen cannot be negative")
	}
	// Check existence of root files
	if _, err := os.Stat(interRootCert); err != nil {
		return fmt.Errorf("root certificate file issue: %w", err)
	}
	if _, err := os.Stat(interRootKey); err != nil {
		return fmt.Errorf("root key file issue: %w", err)
	}
	if _, err := os.Stat(interRootPassFile); err != nil {
		return fmt.Errorf("root passphrase file issue: %w", err)
	}
	if _, err := os.Stat(interPassphraseFile); err != nil {
		return fmt.Errorf("intermediate passphrase file issue: %w", err)
	}
	return nil
}
