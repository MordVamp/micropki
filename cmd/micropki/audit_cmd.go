package main

import (
	"encoding/json"
	"fmt"

	"micropki/internal/audit"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log operations",
	Long:  `Query and verify the cryptographic audit log.`,
}

var auditQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query audit log entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		logFile, _ := cmd.Flags().GetString("log-file")
		operation, _ := cmd.Flags().GetString("operation")
		level, _ := cmd.Flags().GetString("level")
		serial, _ := cmd.Flags().GetString("serial")
		from, _ := cmd.Flags().GetString("from")
		to, _ := cmd.Flags().GetString("to")

		entries, err := audit.Query(logFile, audit.QueryOptions{
			Operation: operation,
			Level:     level,
			Serial:    serial,
			From:      from,
			To:        to,
		})
		if err != nil {
			return fmt.Errorf("query failed: %w", err)
		}

		if len(entries) == 0 {
			fmt.Println("No matching audit log entries found.")
			return nil
		}

		for _, e := range entries {
			b, _ := json.MarshalIndent(e, "", "  ")
			fmt.Println(string(b))
		}
		return nil
	},
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify audit log integrity (hash chain + HMAC)",
	RunE: func(cmd *cobra.Command, args []string) error {
		logFile, _ := cmd.Flags().GetString("log-file")
		chainFile, _ := cmd.Flags().GetString("chain-file")

		if err := audit.Verify(logFile, chainFile); err != nil {
			return fmt.Errorf("audit integrity verification FAILED: %w", err)
		}

		fmt.Println("[OK] Audit log integrity verified successfully.")
		return nil
	},
}

func init() {
	// query flags
	auditQueryCmd.Flags().String("log-file", "./pki/audit/audit.log", "Path to audit log file")
	auditQueryCmd.Flags().String("operation", "", "Filter by operation (e.g. compromise_key)")
	auditQueryCmd.Flags().String("level", "", "Filter by level (e.g. AUDIT)")
	auditQueryCmd.Flags().String("serial", "", "Filter by certificate serial number")
	auditQueryCmd.Flags().String("from", "", "Start time filter (RFC3339)")
	auditQueryCmd.Flags().String("to", "", "End time filter (RFC3339)")

	// verify flags
	auditVerifyCmd.Flags().String("log-file", "./pki/audit/audit.log", "Path to audit log file")
	auditVerifyCmd.Flags().String("chain-file", "", "Path to chain.dat file (auto-detected if empty)")

	auditCmd.AddCommand(auditQueryCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	rootCmd.AddCommand(auditCmd)
}
