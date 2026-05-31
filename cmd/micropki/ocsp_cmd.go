package main

import (
	"fmt"
	"net/http"

	"micropki/internal/database"
	"micropki/internal/logger"
	"micropki/internal/ocsp"

	"github.com/spf13/cobra"
)

var ocspCmd = &cobra.Command{
	Use:   "ocsp",
	Short: "OCSP responder operations",
	Long:  `Start and manage the Online Certificate Status Protocol responder.`,
}

var ocspServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the OCSP responder server",
	RunE: func(cmd *cobra.Command, args []string) error {
		port, _ := cmd.Flags().GetInt("port")
		dbPath, _ := cmd.Flags().GetString("db-path")
		certPath, _ := cmd.Flags().GetString("cert")
		keyPath, _ := cmd.Flags().GetString("key")
		caCertPath, _ := cmd.Flags().GetString("ca-cert")

		if err := logger.Init(""); err != nil {
			return err
		}
		defer logger.Close()

		if err := database.InitDB(dbPath); err != nil {
			return fmt.Errorf("db init: %w", err)
		}

		responder, err := ocsp.NewResponder(certPath, keyPath, caCertPath)
		if err != nil {
			return fmt.Errorf("failed to create OCSP responder: %w", err)
		}

		addr := fmt.Sprintf(":%d", port)
		fmt.Printf("Starting OCSP responder on %s\n", addr)
		logger.Info("Starting OCSP responder on %s", addr)

		mux := http.NewServeMux()
		mux.Handle("/ocsp", responder)
		mux.Handle("/", responder) // also accept root path

		return http.ListenAndServe(addr, mux)
	},
}

func init() {
	ocspServeCmd.Flags().Int("port", 8081, "TCP port for OCSP responder")
	ocspServeCmd.Flags().String("db-path", "./pki/micropki.db", "Path to SQLite database")
	ocspServeCmd.Flags().String("cert", "./pki/certs/ocsp.cert.pem", "Path to OCSP responder certificate")
	ocspServeCmd.Flags().String("key", "./pki/certs/ocsp.key.pem", "Path to OCSP responder private key")
	ocspServeCmd.Flags().String("ca-cert", "./pki/certs/intermediate.cert.pem", "Path to issuing CA certificate")

	ocspCmd.AddCommand(ocspServeCmd)
	rootCmd.AddCommand(ocspCmd)
}
