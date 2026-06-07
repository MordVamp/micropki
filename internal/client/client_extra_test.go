package client

import (
	"bytes"
	"testing"
	"micropki/internal/logger"
)

func init() {
	logger.SilenceStderr = true
}

func TestClientCommandsInvalidArgs(t *testing.T) {
	cmds := [][]string{
		{"gen-csr", "--out-csr", "/dev/null/invalid", "--out-key", "/dev/null/invalid", "--subject", "CN=invalid"},
		{"request-cert", "--csr", "/dev/null/invalid", "--ca-url", "http://invalid", "--out-cert", "/dev/null/invalid"},
		{"check-status", "--cert", "/dev/null/invalid", "--ca-cert", "/dev/null/invalid"},
		{"validate", "--cert", "/dev/null/invalid", "--trusted", "/dev/null/invalid"},
	}

	for _, args := range cmds {
		ClientCmd.SetArgs(args)
		var out bytes.Buffer
		ClientCmd.SetOut(&out)
		ClientCmd.SetErr(&out)
		_ = ClientCmd.Execute()
	}
}
