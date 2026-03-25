package client

import (
	"github.com/spf13/cobra"
)

// ClientCmd represents the root command for client operations
var ClientCmd = &cobra.Command{
	Use:   "client",
	Short: "Client operations for certificate management",
	Long:  `Generate CSRs, request certificates, and validate chains natively.`,
}
