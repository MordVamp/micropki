package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"

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
		dbPath, _ := cmd.Flags().GetString("db-path")
		if logFile == "" {
			logFile = filepath.Join(filepath.Dir(dbPath), "audit", "audit.log")
		}
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
		dbPath, _ := cmd.Flags().GetString("db-path")
		if logFile == "" {
			logFile = filepath.Join(filepath.Dir(dbPath), "audit", "audit.log")
		}
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
	auditQueryCmd.Flags().String("log-file", "", "Path to audit log file (overrides db-path)")
	auditQueryCmd.Flags().String("db-path", "./pki/micropki.db", "SQLite DB path to infer audit log location")
	auditQueryCmd.Flags().String("operation", "", "Filter by operation (e.g. compromise_key)")
	auditQueryCmd.Flags().String("level", "", "Filter by level (e.g. AUDIT)")
	auditQueryCmd.Flags().String("serial", "", "Filter by certificate serial number")
	auditQueryCmd.Flags().String("from", "", "Start time filter (RFC3339)")
	auditQueryCmd.Flags().String("to", "", "End time filter (RFC3339)")

	// verify flags
	auditVerifyCmd.Flags().String("log-file", "", "Path to audit log file (overrides db-path)")
	auditVerifyCmd.Flags().String("db-path", "./pki/micropki.db", "SQLite DB path to infer audit log location")
	auditVerifyCmd.Flags().String("chain-file", "", "Path to chain.dat file (auto-detected if empty)")

	auditCmd.AddCommand(auditQueryCmd)
	auditCmd.AddCommand(auditVerifyCmd)
	rootCmd.AddCommand(auditCmd)
}
