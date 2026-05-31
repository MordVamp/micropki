package client

import (
	"testing"
)

func TestClientErrorPaths(t *testing.T) {
	_ = checkStatusCmd.RunE(checkStatusCmd, []string{"test"})
	_ = validateCmd.RunE(validateCmd, []string{"test"})
	_ = genCsrCmd.RunE(genCsrCmd, []string{"test"})
	_ = requestCertCmd.RunE(requestCertCmd, []string{"test"})
}
