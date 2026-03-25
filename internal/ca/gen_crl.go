package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"micropki/internal/crl"
	internalcrypto "micropki/internal/crypto"
	"micropki/internal/database"
	"micropki/internal/logger"

	"github.com/spf13/cobra"
)

var genCrlCmd = &cobra.Command{
	Use:   "gen-crl",
	Short: "Generate a Certificate Revocation List (CRL) for a CA",
	RunE: func(cmd *cobra.Command, args []string) error {
		caType, _ := cmd.Flags().GetString("ca")
		nextUpdateDays, _ := cmd.Flags().GetInt("next-update")
		outFile, _ := cmd.Flags().GetString("out-file")
		dbPath, _ := cmd.Flags().GetString("db-path")
		passphraseFile, _ := cmd.Flags().GetString("passphrase-file")

		if err := logger.Init(""); err != nil {
			return err
		}
		defer logger.Close()

		if err := database.InitDB(dbPath); err != nil {
			logger.Error("Failed to init db: %v", err)
			return err
		}

		// Determine paths based on 'ca' parameter if out-file isn't explicitly set
		var certPath, keyPath string
		baseDir := filepath.Dir(dbPath)
		caType = strings.ToLower(caType)

		if caType == "root" {
			certPath = filepath.Join(baseDir, "certs", "ca.cert.pem")
			keyPath = filepath.Join(baseDir, "private", "ca.key.pem")
			if outFile == "" {
				outFile = filepath.Join(baseDir, "crl", "root.crl.pem")
			}
		} else if caType == "intermediate" {
			certPath = filepath.Join(baseDir, "certs", "intermediate.cert.pem")
			keyPath = filepath.Join(baseDir, "private", "intermediate.key.pem")
			if outFile == "" {
				outFile = filepath.Join(baseDir, "crl", "intermediate.crl.pem")
			}
		} else {
			// Assume caType is actually a path to a cert.
			certPath = caType
			// We can't easily guess the key path, so this might fail unless standard fallback is used.
			return fmt.Errorf("--ca must be 'root' or 'intermediate'")
		}

		// Read cert
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate %s: %w", certPath, err)
		}
		block, _ := pem.Decode(certPEM)
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		// Read key
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read CA private key %s: %w", keyPath, err)
		}

		passphrase, err := os.ReadFile(passphraseFile)
		if err != nil {
			return fmt.Errorf("failed to read CA passphrase file %s: %w", passphraseFile, err)
		}
		passphrase = []byte(strings.TrimRight(string(passphrase), "\r\n"))

		caKey, err := internalcrypto.DecryptPrivateKey(keyPEM, passphrase)
		if err != nil {
			return fmt.Errorf("CA key decryption failed: %w", err)
		}

		// Build signers array for crypto.Signer
		signer, ok := caKey.(crypto.Signer)
		if !ok {
			return fmt.Errorf("CA private key does not implement crypto.Signer")
		}

		// Call Generator
		crlPEM, err := crl.GenerateCRL(caCert, signer, nextUpdateDays)
		if err != nil {
			logger.Error("CRL Generation Failed: %v", err)
			return err
		}

		// Ensure directory
		if err := os.MkdirAll(filepath.Dir(outFile), 0700); err != nil {
			return fmt.Errorf("failed to create crl directory: %w", err)
		}

		if err := os.WriteFile(outFile, crlPEM, 0644); err != nil {
			return fmt.Errorf("failed to write CRL file: %w", err)
		}

		// Write path into database metadata so we know where it is
		meta, _ := database.GetCRLMetadata(caCert.Subject.String())
		if meta != nil {
			meta.CRLPath = outFile
			database.UpdateCRLMetadata(*meta)
		}

		fmt.Printf("CRL successfully generated and saved to %s\n", outFile)
		return nil
	},
}

func init() {
	genCrlCmd.Flags().String("ca", "intermediate", "CA to generate CRL for (root or intermediate)")
	genCrlCmd.Flags().Int("next-update", 7, "Next update in days")
	genCrlCmd.Flags().String("out-file", "", "Output file path")
	genCrlCmd.Flags().String("db-path", "./pki/micropki.db", "SQLite DB path")
	genCrlCmd.Flags().String("passphrase-file", "./secrets/intermediate.pass", "File containing passphrase for CA key") // Example default

	CaCmd.AddCommand(genCrlCmd)
}
