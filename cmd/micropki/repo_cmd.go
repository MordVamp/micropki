package main

import (
	"fmt"
	"micropki/internal/database"
	"micropki/internal/logger"
	"micropki/internal/repository"

	"github.com/spf13/cobra"
)

var repoCmd = &cobra.Command{
	Use:   "repo",
	Short: "Repository server operations",
	Long:  `Start and manage the HTTP repository server.`,
}

var repoServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the repository server",
	RunE: func(cmd *cobra.Command, args []string) error {
		host, _ := cmd.Flags().GetString("host")
		port, _ := cmd.Flags().GetInt("port")
		dbPath, _ := cmd.Flags().GetString("db-path")
		certDir, _ := cmd.Flags().GetString("cert-dir")
		
		// Optionally configure log file here if supported
		if err := logger.Init(""); err != nil {
			return err
		}
		defer logger.Close()

		// Initialize Database Connection before starting server
		if err := database.InitDB(dbPath); err != nil {
			logger.Error("Failed to connect to database: %v", err)
			return fmt.Errorf("db init: %w", err)
		}

		server := &repository.Server{
			Host:    host,
			Port:    port,
			DBPath:  dbPath,
			CertDir: certDir,
		}

		fmt.Printf("Starting repository server on %s:%d\n", host, port)
		if err := server.Start(); err != nil {
			logger.Error("Server error: %v", err)
			return err
		}

		return nil
	},
}

var repoStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check repository server status",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Repository server status check is not fully implemented yet.")
		return nil
	},
}

func init() {
	repoServeCmd.Flags().String("host", "127.0.0.1", "Bind address")
	repoServeCmd.Flags().Int("port", 8080, "TCP port")
	repoServeCmd.Flags().String("db-path", "./pki/micropki.db", "Path to SQLite database")
	repoServeCmd.Flags().String("cert-dir", "./pki/certs", "Directory containing CA PEM certificates")
	
	repoCmd.AddCommand(repoServeCmd)
	repoCmd.AddCommand(repoStatusCmd)
	rootCmd.AddCommand(repoCmd)
}
