package ca

import (
	"fmt"
	"micropki/internal/database"
	"micropki/internal/logger"

	"github.com/spf13/cobra"
)

var listCertsCmd = &cobra.Command{
	Use:   "list-certs",
	Short: "List all issued certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, _ := cmd.Flags().GetString("status")
		format, _ := cmd.Flags().GetString("format")
		dbPath, _ := cmd.Flags().GetString("db-path")

		if err := logger.Init(""); err != nil {
			return err
		}
		defer logger.Close()

		if err := database.InitDB(dbPath); err != nil {
			logger.Error("Failed to open database: %v", err)
			return fmt.Errorf("db init: %w", err)
		}

		records, err := database.ListCertificates(status)
		if err != nil {
			logger.Error("Failed to list certificates: %v", err)
			return err
		}

		if format == "json" {
			// A real implementation would serialize, for now basic output
			fmt.Printf("[\n")
			for i, r := range records {
				fmt.Printf(`  {"serial": "%s", "subject": "%s", "status": "%s"}`, r.SerialHex, r.Subject, r.Status)
				if i < len(records)-1 {
					fmt.Print(",")
				}
				fmt.Println()
			}
			fmt.Printf("]\n")
		} else {
			// Table output
			fmt.Printf("%-24s %-8s %-40s %s\n", "SERIAL", "STATUS", "SUBJECT", "EXPIRATION")
			fmt.Println("------------------------------------------------------------------------------------------------")
			for _, r := range records {
				fmt.Printf("%-24s %-8s %-40s %s\n", r.SerialHex, r.Status, TruncateString(r.Subject, 40), r.NotAfter)
			}
		}

		return nil
	},
}

func init() {
	listCertsCmd.Flags().String("status", "", "Filter by status (valid, revoked, expired)")
	listCertsCmd.Flags().String("format", "table", "Output format (table, json)")
	listCertsCmd.Flags().String("db-path", "./pki/micropki.db", "File path for the SQLite database")
	
	CaCmd.AddCommand(listCertsCmd)
}

func TruncateString(s string, l int) string {
	if len(s) > l {
		return s[:l-3] + "..."
	}
	return s
}
