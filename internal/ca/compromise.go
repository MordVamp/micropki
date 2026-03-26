package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"micropki/internal/audit"
	"micropki/internal/database"
	"micropki/internal/logger"

	"github.com/spf13/cobra"
)

var compromiseCmd = &cobra.Command{
	Use:   "compromise",
	Short: "Simulate private key compromise and immediately revoke certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath, _ := cmd.Flags().GetString("cert")
		dbPath, _ := cmd.Flags().GetString("db-path")
		reason, _ := cmd.Flags().GetString("reason")

		if err := logger.Init(""); err != nil {
			return err
		}
		defer logger.Close()

		if err := database.InitDB(dbPath); err != nil {
			return err
		}

		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("failed to read cert file: %v", err)
		}

		block, _ := pem.Decode(certBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode PEM certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}

		serialHex := fmt.Sprintf("%x", cert.SerialNumber)

		// 1. Revoke the certificate
		err = database.RevokeCertificate(serialHex, reason)
		if err != nil {
			logger.Error("Revocation failed: %v", err)
			return err
		}

		// 2. Hash public key and mark compromised
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to marshal public key: %v", err)
		}
		h := sha256.Sum256(pubKeyBytes)
		pubKeyHash := hex.EncodeToString(h[:])

		now := time.Now().UTC().Format(time.RFC3339)
		err = database.MarkKeyCompromised(pubKeyHash, serialHex, now, reason)
		if err != nil {
			return fmt.Errorf("failed to mark key compromised: %v", err)
		}

		// 3. Generate high-severity audit log
		metadata := map[string]interface{}{
			"serial":          serialHex,
			"subject":         cert.Subject.String(),
			"reason":          reason,
			"public_key_hash": pubKeyHash,
		}
		if err := audit.LogEvent("AUDIT", "compromise_key", "success", "Private key marked as compromised", metadata); err != nil {
			logger.Warning("Failed to write audit log: %v", err)
		}

		fmt.Printf("[ALARM] Certificate %s revoked and key marked as compromised.\n", serialHex)
		return nil
	},
}

func init() {
	compromiseCmd.Flags().String("cert", "", "Path to the compromised certificate")
	compromiseCmd.Flags().String("reason", "keyCompromise", "Reason code")
	compromiseCmd.Flags().Bool("force", false, "Force execution")
	compromiseCmd.Flags().String("db-path", "./pki/micropki.db", "SQLite DB path")

	cobra.MarkFlagRequired(compromiseCmd.Flags(), "cert")

	CaCmd.AddCommand(compromiseCmd)
}
