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
		caCert, _ := cmd.Flags().GetString("ca-cert")
		caKey, _ := cmd.Flags().GetString("ca-key")
		caPass, _ := cmd.Flags().GetString("ca-pass-file")
		rateLimit, _ := cmd.Flags().GetInt("rate-limit")
		rateBurst, _ := cmd.Flags().GetInt("rate-burst")
		
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
			Host:       host,
			Port:       port,
			DBPath:     dbPath,
			CertDir:    certDir,
			CACertPath: caCert,
			CAKeyPath:  caKey,
			CAPassPath: caPass,
			RateLimit:  rateLimit,
			RateBurst:  rateBurst,
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
	repoServeCmd.Flags().String("ca-cert", "./pki/certs/intermediate.cert.pem", "Path to CA internal cert for issuances")
	repoServeCmd.Flags().String("ca-key", "./pki/private/intermediate.key.pem", "Path to CA internal key for issuances")
	repoServeCmd.Flags().String("ca-pass-file", "./secrets/intermediate.pass", "Path to CA passkey file")
	repoServeCmd.Flags().Int("rate-limit", 0, "Requests per second limit (0 to disable)")
	repoServeCmd.Flags().Int("rate-burst", 10, "Burst tolerance for rate limiting")
	
	repoCmd.AddCommand(repoServeCmd)
	repoCmd.AddCommand(repoStatusCmd)
	rootCmd.AddCommand(repoCmd)
}
