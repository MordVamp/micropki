package client

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var requestCertCmd = &cobra.Command{
	Use:   "request-cert",
	Short: "Submit a CSR to the CA repository natively and retrieve the issued certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		csrPath, _ := cmd.Flags().GetString("csr")
		template, _ := cmd.Flags().GetString("template")
		caUrl, _ := cmd.Flags().GetString("ca-url")
		outCert, _ := cmd.Flags().GetString("out-cert")

		csrData, err := os.ReadFile(csrPath)
		if err != nil {
			return fmt.Errorf("failed to read requested CSR locally: %w", err)
		}

		apiURL := fmt.Sprintf("%s/request-cert?template=%s", caUrl, template)
		req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(csrData))
		if err != nil {
			return err
		}
		
		req.Header.Set("Content-Type", "application/x-pem-file")
		
		// Authenticate securely (Simulated API for Sprint 6 Demo limits)
		req.Header.Set("X-API-Key", "changeme")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed submitting CSR bounding over HTTP natively: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("CA Repository returned error (%d): %s", resp.StatusCode, string(body))
		}

		if err := os.WriteFile(outCert, body, 0644); err != nil {
			return fmt.Errorf("failed writing downloaded raw cert safely: %w", err)
		}

		fmt.Printf("Certificate successfully received dynamically via HTTP and tracked to %s\n", outCert)
		return nil
	},
}

func init() {
	flags := requestCertCmd.Flags()
	flags.String("csr", "./request.csr.pem", "Path to CSR file (PEM)")
	flags.String("template", "server", "Certificate template constraint: server, client, code_signing")
	flags.String("ca-url", "http://127.0.0.1:8080", "Base URL mapped to the repository active subsystem")
	flags.String("out-cert", "./cert.pem", "Output file tracking the resulting signed certificate (PEM)")
	
	ClientCmd.AddCommand(requestCertCmd)
}
