package ca

import (
	"fmt"
	"micropki/internal/database"
	"micropki/internal/logger"
	"strings"

	"github.com/spf13/cobra"
)

var showCertCmd = &cobra.Command{
	Use:   "show-cert <serial>",
	Short: "Show a single certificate by serial number",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serial := strings.TrimSpace(args[0])
		dbPath, _ := cmd.Flags().GetString("db-path")

		if err := logger.Init(""); err != nil {
			return err
		}
		defer logger.Close()

		if err := database.InitDB(dbPath); err != nil {
			logger.Error("Failed to open database: %v", err)
			return fmt.Errorf("db init: %w", err)
		}

		logger.Info("Retrieving certificate %s via ca show-cert", serial)

		record, err := database.GetCertificateBySerial(serial)
		if err != nil {
			logger.Error("Database query failed: %v", err)
			return err
		}

		if record == nil {
			fmt.Printf("Certificate with serial %s not found.\n", serial)
			return nil
		}

		// Print the PEM content
		fmt.Print(record.CertPEM)

		return nil
	},
}

func init() {
	showCertCmd.Flags().String("db-path", "./pki/micropki.db", "File path for the SQLite database")
	
	CaCmd.AddCommand(showCertCmd)
}
