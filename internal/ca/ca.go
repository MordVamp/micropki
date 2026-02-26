package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"micropki/internal/certs"
	internalcrypto "micropki/internal/crypto"
	"micropki/internal/logger"
	"micropki/internal/policy"

	"github.com/spf13/cobra"
)

var (
	subject        string
	keyType        string
	keySize        int
	passphraseFile string
	outDir         string
	validityDays   int
	logFile        string
)

// Cmd is the `ca init` subcommand.
var Cmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a self-signed Root CA",
	Long:  `Generate a self-signed Root CA certificate and encrypted private key.`,
	RunE:  runInit,
}

func init() {
	flags := Cmd.Flags()
	flags.StringVar(&subject, "subject", "", "Distinguished Name (e.g., 'CN=My Root CA,O=Demo,C=US')")
	flags.StringVar(&keyType, "key-type", "rsa", "Key type: rsa or ecc")
	flags.IntVar(&keySize, "key-size", 4096, "Key size in bits (4096 for RSA, 384 for ECC)")
	flags.StringVar(&passphraseFile, "passphrase-file", "", "Path to file containing passphrase for private key encryption")
	flags.StringVar(&outDir, "out-dir", "./pki", "Output directory")
	flags.IntVar(&validityDays, "validity-days", 3650, "Validity period in days")
	flags.StringVar(&logFile, "log-file", "", "Log file path (default: stderr)")

	cobra.MarkFlagRequired(flags, "subject")
	cobra.MarkFlagRequired(flags, "passphrase-file")
}

func runInit(cmd *cobra.Command, args []string) error {
	if err := logger.Init(logFile); err != nil {
		return fmt.Errorf("failed to init logger: %w", err)
	}
	defer logger.Close()

	logger.Info("Starting Root CA initialization")

	if err := validateArgs(); err != nil {
		logger.Error("Validation failed: %v", err)
		return err
	}

	passphrase, err := os.ReadFile(passphraseFile)
	if err != nil {
		logger.Error("Failed to read passphrase file: %v", err)
		return fmt.Errorf("cannot read passphrase file: %w", err)
	}
	passphrase = []byte(strings.TrimRight(string(passphrase), "\r\n"))
	logger.Info("Passphrase loaded (length %d bytes)", len(passphrase))

	name, err := ParseDN(subject)
	if err != nil {
		logger.Error("Invalid subject DN: %v", err)
		return fmt.Errorf("invalid subject: %w", err)
	}

	privateDir := filepath.Join(outDir, "private")
	certsDir := filepath.Join(outDir, "certs")
	for _, dir := range []string{privateDir, certsDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			logger.Error("Failed to create directory %s: %v", dir, err)
			return fmt.Errorf("cannot create directory %s: %w", dir, err)
		}
	}

	logger.Info("Generating %s key (%d bits)", keyType, keySize)
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	switch keyType {
	case "rsa":
		rsaKey, err := internalcrypto.GenerateRSAKey(keySize)
		if err != nil {
			logger.Error("RSA key generation failed: %v", err)
			return err
		}
		privKey = rsaKey
		pubKey = &rsaKey.PublicKey
	case "ecc":
		eccKey, err := internalcrypto.GenerateECCKey()
		if err != nil {
			logger.Error("ECC key generation failed: %v", err)
			return err
		}
		privKey = eccKey
		pubKey = &eccKey.PublicKey
	default:
		return fmt.Errorf("unsupported key type")
	}
	logger.Info("Key generation completed")

	serialBytes := make([]byte, 20)
	if _, err := rand.Read(serialBytes); err != nil {
		logger.Error("Failed to generate serial number: %v", err)
		return fmt.Errorf("serial generation failed: %w", err)
	}
	serial := new(big.Int).SetBytes(serialBytes)
	logger.Info("Serial number generated: %x", serial)

	logger.Info("Creating self-signed certificate, validity %d days", validityDays)
	certPEM, err := certs.GenerateRootCertificate(&name, pubKey, privKey, validityDays, serial)
	if err != nil {
		logger.Error("Certificate generation failed: %v", err)
		return fmt.Errorf("certificate creation failed: %w", err)
	}
	logger.Info("Certificate generated")

	keyPath := filepath.Join(privateDir, "ca.key.pem")
	logger.Info("Encrypting private key and saving to %s", keyPath)
	encryptedKey, err := internalcrypto.EncryptPrivateKey(privKey, passphrase)
	if err != nil {
		logger.Error("Key encryption failed: %v", err)
		return fmt.Errorf("key encryption failed: %w", err)
	}
	if err := os.WriteFile(keyPath, encryptedKey, 0600); err != nil {
		logger.Error("Failed to write private key: %v", err)
		return fmt.Errorf("cannot write private key: %w", err)
	}
	logger.Info("Private key saved")

	certPath := filepath.Join(certsDir, "ca.cert.pem")
	logger.Info("Saving certificate to %s", certPath)
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		logger.Error("Failed to write certificate: %v", err)
		return fmt.Errorf("cannot write certificate: %w", err)
	}
	logger.Info("Certificate saved")

	policyPath := filepath.Join(outDir, "policy.txt")
	logger.Info("Writing policy document to %s", policyPath)
	if err := policy.Write(policyPath, &name, serial, validityDays, keyType, keySize); err != nil {
		logger.Error("Failed to write policy: %v", err)
		return fmt.Errorf("policy creation failed: %w", err)
	}
	logger.Info("Policy document created")

	logger.Info("Root CA initialization completed successfully")
	fmt.Printf("Root CA successfully created in %s\n", outDir)
	return nil
}

func validateArgs() error {
	if subject == "" {
		return fmt.Errorf("subject cannot be empty")
	}
	if keyType != "rsa" && keyType != "ecc" {
		return fmt.Errorf("key-type must be 'rsa' or 'ecc'")
	}
	if keyType == "rsa" && keySize != 4096 {
		return fmt.Errorf("RSA key size must be 4096")
	}
	if keyType == "ecc" && keySize != 384 {
		return fmt.Errorf("ECC key size must be 384")
	}
	if validityDays <= 0 {
		return fmt.Errorf("validity-days must be positive")
	}
	if _, err := os.Stat(passphraseFile); err != nil {
		return fmt.Errorf("passphrase file issue: %w", err)
	}
	return nil
}

// ParseDN converts a string like "CN=My CA,O=Demo,C=US" into pkix.Name.
func ParseDN(dn string) (pkix.Name, error) {
	name := pkix.Name{}
	if strings.HasPrefix(dn, "/") {
		dn = dn[1:]
	}
	var parts []string
	if strings.Contains(dn, ",") {
		parts = strings.Split(dn, ",")
	} else if strings.Contains(dn, "/") {
		parts = strings.Split(dn, "/")
	} else {
		parts = []string{dn}
	}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return name, fmt.Errorf("invalid DN part: %s", part)
		}
		key := strings.ToUpper(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])
		switch key {
		case "CN":
			name.CommonName = value
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "C":
			name.Country = []string{value}
		case "L":
			name.Locality = []string{value}
		case "ST":
			name.Province = []string{value}
		case "STREET":
			name.StreetAddress = []string{value}
		case "POSTALCODE":
			name.PostalCode = []string{value}
		}
	}
	return name, nil
}
