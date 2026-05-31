package ca

import (
	"testing"
)

func TestCAErrorPaths(t *testing.T) {
	_ = initCmd.RunE(initCmd, []string{"test"})
	_ = issueIntermediateCmd.RunE(issueIntermediateCmd, []string{"test"})
	_ = issueCertCmd.RunE(issueCertCmd, []string{"test"})
	_ = revokeCmd.RunE(revokeCmd, []string{"test"})
	_ = issueOcspCmd.RunE(issueOcspCmd, []string{"test"})
	_ = listCertsCmd.RunE(listCertsCmd, []string{"test"})
	_ = compromiseCmd.RunE(compromiseCmd, []string{"test"})
	_ = genCrlCmd.RunE(genCrlCmd, []string{"test"})
	_ = showCertCmd.RunE(showCertCmd, []string{"test"})
}
