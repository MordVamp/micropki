package client

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type ValidationStep struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type ValidationResult struct {
	OverallStatus string           `json:"overall_status"`
	Error         string           `json:"error,omitempty"`
	Steps         []ValidationStep `json:"steps"`
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Perform full X.509 RFC 5280 certificate chain validation engine natively via MicroPKI bounds",
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath, _ := cmd.Flags().GetString("cert")
		untrustedPaths, _ := cmd.Flags().GetStringSlice("untrusted")
		trustedPath, _ := cmd.Flags().GetString("trusted")
		validationTimeStr, _ := cmd.Flags().GetString("validation-time")
		mode, _ := cmd.Flags().GetString("mode")
		format, _ := cmd.Flags().GetString("format")
		// crl and ocsp flags skipped here; handled later

		now := time.Now().UTC()
		if validationTimeStr != "" {
			parsed, err := time.Parse(time.RFC3339, validationTimeStr)
			if err != nil {
				return fmt.Errorf("invalid validation-time format (expected RFC3339): %w", err)
			}
			now = parsed
		}

		result := ValidationResult{OverallStatus: "FAILED", Steps: []ValidationStep{}}

		leaf, err := loadCertificate(certPath)
		if err != nil {
			result.Error = fmt.Sprintf("Failed to load leaf certificate: %v", err)
			printResult(result, format)
			return nil
		}
		result.Steps = append(result.Steps, ValidationStep{Name: "Load Leaf", Status: "PASS", Detail: leaf.Subject.String()})

		untrusted := []*x509.Certificate{}
		for _, p := range untrustedPaths {
			certs, err := loadCertificates(p)
			if err == nil {
				untrusted = append(untrusted, certs...)
			}
		}

		trusted, err := loadCertificates(trustedPath)
		if err != nil || len(trusted) == 0 {
			result.Error = fmt.Sprintf("Failed to load trusted root bundle: %v", err)
			printResult(result, format)
			return nil
		}
		result.Steps = append(result.Steps, ValidationStep{Name: "Load Trust Store", Status: "PASS", Detail: fmt.Sprintf("%d roots loaded", len(trusted))})

		// 1. Build Chain
		chain, err := buildChain(leaf, untrusted, trusted)
		if err != nil {
			result.Error = fmt.Sprintf("Path construction failed: %v", err)
			printResult(result, format)
			return nil
		}
		
		chainNames := []string{}
		for _, c := range chain {
			chainNames = append(chainNames, c.Subject.CommonName)
		}
		result.Steps = append(result.Steps, ValidationStep{Name: "Build Chain", Status: "PASS", Detail: strings.Join(chainNames, " -> ")})

		// 2. Cryptographic Validation (Root -> Leaf)
		err = validateChainCryptographically(chain, now)
		if err != nil {
			result.Error = fmt.Sprintf("Validation engine failed: %v", err)
			printResult(result, format)
			return nil
		}
		result.Steps = append(result.Steps, ValidationStep{Name: "Cryptographic Path Validation checks", Status: "PASS", Detail: "Signature, Time bounds, and BasicConstraints matching path lengths globally valid."})

		// 3. Optional Revocation
		if mode == "full" {
			// Integrate revocation check. For Sprint 6 demo simplicity inside `validate`, we will just note it passes if checkStatus succeeds.
			// The explicit `client check-status` handles logic deeply. 
			// We can call RevocationStatus here recursively on chain certificates
			crlOpt, _ := cmd.Flags().GetString("crl")
			useOcsp, _ := cmd.Flags().GetBool("ocsp")
			
			for i := 0; i < len(chain)-1; i++ { // check all except root
				subjectCert := chain[i]
				issuerCert := chain[i+1]
				
				revStatus, reason, err := resolveRevocation(subjectCert, issuerCert, crlOpt, useOcsp)
				if err != nil {
					result.Error = fmt.Sprintf("Revocation check failed on %s: %v", subjectCert.Subject.CommonName, err)
					printResult(result, format)
					return nil
				}
				if revStatus != "good" {
					result.Error = fmt.Sprintf("Certificate %s is %s: %s", subjectCert.Subject.CommonName, revStatus, reason)
					printResult(result, format)
					return nil
				}
			}
			result.Steps = append(result.Steps, ValidationStep{Name: "Revocation Enforcement (OCSP/CRL)", Status: "PASS", Detail: "All chain elements returned good."})
		}

		result.OverallStatus = "SUCCESS"
		printResult(result, format)
		return nil
	},
}

func printResult(r ValidationResult, format string) {
	if format == "json" {
		bz, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(bz))
	} else {
		fmt.Printf("Validation Engine Result: %s\n", r.OverallStatus)
		if r.Error != "" {
			fmt.Printf("Critical Faiure: %s\n", r.Error)
		}
		fmt.Println("\nValidation Steps Executed:")
		for i, s := range r.Steps {
			fmt.Printf(" %d. %s [%s] - %s\n", i+1, s.Name, s.Status, s.Detail)
		}
	}
}

// buildChain builds backwards from leaf to root iteratively mapping Issuers
func buildChain(leaf *x509.Certificate, untrusted []*x509.Certificate, trusted []*x509.Certificate) ([]*x509.Certificate, error) {
	chain := []*x509.Certificate{leaf}
	current := leaf

	for {
		// Is current signed by any trusted Root?
		var foundRoot *x509.Certificate
		for _, r := range trusted {
			if current.Issuer.String() == r.Subject.String() {
				// Verify signature to be sure
				if current.CheckSignatureFrom(r) == nil {
					foundRoot = r
					break
				}
			}
		}
		if foundRoot != nil {
			if current != foundRoot { // Avoid appending roots twice if self-signed root is leaf
				chain = append(chain, foundRoot)
			}
			return chain, nil
		}

		// Look into untrusted pool for issuer
		var foundInter *x509.Certificate
		for _, u := range untrusted {
			if current.Issuer.String() == u.Subject.String() {
				if current.CheckSignatureFrom(u) == nil {
					foundInter = u
					break
				}
			}
		}

		if foundInter != nil {
			// Cycle check
			for _, c := range chain {
				if c.Subject.String() == foundInter.Subject.String() {
					return nil, fmt.Errorf("certificate cycle detected involving %s", foundInter.Subject.CommonName)
				}
			}
			chain = append(chain, foundInter)
			current = foundInter
		} else {
			return nil, fmt.Errorf("issuer not found locally for %s", current.Subject.CommonName)
		}
	}
}

func validateChainCryptographically(chain []*x509.Certificate, now time.Time) error {
	// Chain structure: [Leaf, Inter1, ..., Root]
	// Traverse from Root downwards to dynamically track maxPathLen restrictions
	maxPathLen := -1

	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]

		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("certificate %s outside of valid time bounds at reference %s", cert.Subject.CommonName, now.Format(time.RFC3339))
		}

		if i < len(chain)-1 {
			parent := chain[i+1]
			if err := cert.CheckSignatureFrom(parent); err != nil {
				return fmt.Errorf("invalid signature on %s from %s", cert.Subject.CommonName, parent.Subject.CommonName)
			}
		}

		if i > 0 { // CA (Roots & Intermediates)
			if !cert.IsCA {
				return fmt.Errorf("certificate %s used as issuer but missing IsCA=true Basic Constraint", cert.Subject.CommonName)
			}
			if cert.KeyUsage != 0 && (cert.KeyUsage&x509.KeyUsageCertSign) == 0 {
				return fmt.Errorf("issuer %s missing critical KeyUsageCertSign flag", cert.Subject.CommonName)
			}

			if maxPathLen != -1 {
				if maxPathLen == 0 {
					return fmt.Errorf("path length constraint exceeded at %s", cert.Subject.CommonName)
				}
				maxPathLen--
			}

			// Capture newly introduced restriction limits propagating downwards
			if cert.MaxPathLenZero {
				maxPathLen = 0
			} else if cert.MaxPathLen > 0 {
				if maxPathLen == -1 || cert.MaxPathLen < maxPathLen {
					maxPathLen = cert.MaxPathLen
				}
			}
		}
	}
	return nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM file block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func loadCertificates(path string) ([]*x509.Certificate, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
		certPEM = rest
	}
	return certs, nil
}

func init() {
	flags := validateCmd.Flags()
	flags.String("cert", "", "Path to leaf certificate (PEM)")
	flags.StringSlice("untrusted", []string{}, "Path to untrusted intermediate certificate bundles (PEM)")
	flags.String("trusted", "./pki/certs/ca.cert.pem", "Path to trusted Root CA bundle (PEM)")
	flags.String("crl", "", "Optional static CRL local file path for fallback")
	flags.Bool("ocsp", false, "Enable OCSP remote status checks")
	flags.String("mode", "full", "Validation mode: chain (signature only) or full (with revocation)")
	flags.String("validation-time", "", "Reference time constraint against which validity bounds are mapped (RFC3339)")
	flags.String("format", "text", "Output structure style (text or json)")

	cobra.MarkFlagRequired(flags, "cert")
	ClientCmd.AddCommand(validateCmd)
}
