package ca

import (
	"fmt"
	"micropki/internal/database"
	"micropki/internal/logger"
	"strings"

	"github.com/spf13/cobra"
)

var revokeCmd = &cobra.Command{
	Use:   "revoke <serial>",
	Short: "Revoke a previously issued certificate",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serial := strings.TrimSpace(args[0])
		reason, _ := cmd.Flags().GetString("reason")
		dbPath, _ := cmd.Flags().GetString("db-path")

		if err := logger.Init(""); err != nil {
			return err
		}
		defer logger.Close()

		if err := database.InitDB(dbPath); err != nil {
			logger.Error("Failed to init db: %v", err)
			return err
		}

		// RFC 5280 validation
		validReasons := map[string]bool{
			"unspecified": true, "keycompromise": true, "cacompromise": true,
			"affiliationchanged": true, "superseded": true, "cessationofoperation": true,
			"certificatehold": true, "removefromcrl": true, "privilegewithdrawn": true, "aacompromise": true,
		}
		
		if !validReasons[strings.ToLower(reason)] {
			return fmt.Errorf("invalid revocation reason: %s", reason)
		}

		err := database.RevokeCertificate(serial, reason)
		if err != nil {
			if strings.Contains(err.Error(), "not found or already revoked") {
				logger.Warning("Certificate %s is already revoked or missing", serial)
				fmt.Println("Certificate already revoked or missing. No action taken.")
				return nil
			}
			return fmt.Errorf("revocation failed: %w", err)
		}

		fmt.Printf("Certificate %s successfully revoked (reason: %s).\n", serial, reason)
		return nil
	},
}

func init() {
	revokeCmd.Flags().String("reason", "unspecified", "Revocation reason code")
	revokeCmd.Flags().Bool("force", false, "Skip confirmation prompts (auto-true for CLI)")
	revokeCmd.Flags().String("db-path", "./pki/micropki.db", "SQLite DB path")

	CaCmd.AddCommand(revokeCmd)
}
