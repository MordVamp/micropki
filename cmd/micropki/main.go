package main

import (
	"os"

	"micropki/internal/ca"
	"micropki/internal/logger"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "micropki",
	Short: "MicroPKI - A minimal PKI implementation",
	Long:  `MicroPKI is a single-handed PKI tool that demonstrates core concepts.`,
}

func init() {
	rootCmd.AddCommand(ca.Cmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Error("command failed: %v", err)
		os.Exit(1)
	}
}
