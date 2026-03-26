package client

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	internalcrypto "micropki/internal/crypto"
	"micropki/internal/logger"

	"github.com/spf13/cobra"
)

var genCsrCmd = &cobra.Command{
	Use:   "gen-csr",
	Short: "Generate a private key and a PKCS#10 Certificate Signing Request (CSR)",
	RunE: func(cmd *cobra.Command, args []string) error {
		subjectStr, _ := cmd.Flags().GetString("subject")
		keyType, _ := cmd.Flags().GetString("key-type")
		keySize, _ := cmd.Flags().GetInt("key-size")
		sans, _ := cmd.Flags().GetStringSlice("san")
		outKey, _ := cmd.Flags().GetString("out-key")
		outCsr, _ := cmd.Flags().GetString("out-csr")

		// We assume no log file option for brevity, standard stderr is fine
		logger.Init("")
		defer logger.Close()

		logger.Info("Generating %s key (%d bits) for CSR", keyType, keySize)

		var privKey crypto.PrivateKey
		switch strings.ToLower(keyType) {
		case "rsa":
			k, err := internalcrypto.GenerateRSAKey(keySize)
			if err != nil {
				return err
			}
			privKey = k
		case "ecc":
			k, err := internalcrypto.GenerateECCKey()
			if err != nil {
				return err
			}
			privKey = k
		default:
			return fmt.Errorf("unsupported key type: %s", keyType)
		}

		// Simple DN parser for CN
		var cn string
		for _, part := range strings.Split(subjectStr, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToUpper(part), "CN=") {
				cn = strings.TrimPrefix(part, "CN=")
				break
			}
		}

		if cn == "" {
			return fmt.Errorf("subject must contain at least a CN (Common Name)")
		}

		subject := pkix.Name{
			CommonName: cn,
		}

		var dnsNames []string
		for _, san := range sans {
			if strings.HasPrefix(san, "dns:") {
				dns := strings.TrimPrefix(san, "dns:")
				if strings.HasPrefix(dns, "*.") {
					return fmt.Errorf("wildcard certificates (*.domain) are forbidden by policy")
				}
				dnsNames = append(dnsNames, dns)
			}
		}

		template := &x509.CertificateRequest{
			Subject:            subject,
			SignatureAlgorithm: x509.SHA256WithRSA, // Will dynamically adjust based on key type within CreateCertificateRequest typically
			DNSNames:           dnsNames,
		}

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
		if err != nil {
			return fmt.Errorf("failed to create CSR: %w", err)
		}

		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
		
		keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

		os.MkdirAll(filepath.Dir(outKey), 0700)
		os.MkdirAll(filepath.Dir(outCsr), 0700)

		if err := os.WriteFile(outKey, keyPEM, 0600); err != nil {
			return fmt.Errorf("failed writing private key: %w", err)
		}
		
		if err := os.WriteFile(outCsr, csrPEM, 0644); err != nil {
			return fmt.Errorf("failed writing csr: %w", err)
		}

		fmt.Printf("WARNING: Private key is stored unencrypted at %s\n", outKey)
		fmt.Printf("CSR successfully saved to %s\n", outCsr)

		return nil
	},
}

func init() {
	flags := genCsrCmd.Flags()
	flags.String("subject", "", "Distinguished Name, e.g. CN=app.example.com")
	flags.String("key-type", "rsa", "Key type: rsa or ecc")
	flags.Int("key-size", 2048, "Key size in bits")
	flags.StringSlice("san", []string{}, "Subject Alternative Name(s)")
	flags.String("out-key", "./key.pem", "Output file for private key (unencrypted PEM)")
	flags.String("out-csr", "./request.csr.pem", "Output file for CSR (PEM)")

	cobra.MarkFlagRequired(flags, "subject")
	ClientCmd.AddCommand(genCsrCmd)
}
