package main

import (
	"fmt"
	"micropki/internal/database"
	"micropki/internal/logger"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Database operations",
	Long:  `Manage the MicroPKI database.`,
}

var dbInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the database schema",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := logger.Init(""); err != nil {
			return err
		}
		defer logger.Close()

		dbPath, _ := cmd.Flags().GetString("db-path")
		if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
			return fmt.Errorf("failed to create database directory: %w", err)
		}

		if err := database.InitDB(dbPath); err != nil {
			return fmt.Errorf("database initialization failed: %w", err)
		}

		fmt.Printf("Database successfully initialized at %s\n", dbPath)
		return nil
	},
}

func init() {
	dbInitCmd.Flags().String("db-path", "./pki/micropki.db", "File path for the SQLite database")
	dbCmd.AddCommand(dbInitCmd)
	rootCmd.AddCommand(dbCmd)
}
