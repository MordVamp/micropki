package client

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"micropki/internal/logger"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ocsp"
)

var checkStatusCmd = &cobra.Command{
	Use:   "check-status",
	Short: "Check revocation status of a certificate using OCSP with CRL fallback natively",
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath, _ := cmd.Flags().GetString("cert")
		caCertPath, _ := cmd.Flags().GetString("ca-cert")
		crlOpt, _ := cmd.Flags().GetString("crl")
		ocspURLOpt, _ := cmd.Flags().GetString("ocsp-url")

		if err := logger.Init(""); err != nil {
			return err
		}
		defer logger.Close()

		cert, err := loadCertificate(certPath)
		if err != nil {
			return err
		}

		issuer, err := loadCertificate(caCertPath)
		if err != nil {
			return err
		}

		// Inject override to AIA
		if ocspURLOpt != "" {
			cert.OCSPServer = []string{ocspURLOpt}
		}

		status, reason, err := resolveRevocation(cert, issuer, crlOpt, true)
		if err != nil {
			fmt.Printf("Status: unknown\nDetails: %v\n", err)
			return nil
		}

		fmt.Printf("Status: %s\n", status)
		if status == "revoked" {
			fmt.Printf("Reason: %s\n", reason)
		}
		return nil
	},
}

func init() {
	flags := checkStatusCmd.Flags()
	flags.String("cert", "", "Path to leaf certificate (PEM)")
	flags.String("ca-cert", "", "Path to issuer CA certificate (PEM)")
	flags.String("crl", "", "Optional static CRL location overriding CDP")
	flags.String("ocsp-url", "", "Optional OCSP responder overriding AIA")
	
	cobra.MarkFlagRequired(flags, "cert")
	cobra.MarkFlagRequired(flags, "ca-cert")
	ClientCmd.AddCommand(checkStatusCmd)
}

// resolveRevocation enforces native OCSP priority followed by CDP fetching/parsing
func resolveRevocation(cert *x509.Certificate, issuer *x509.Certificate, crlOverride string, useOcsp bool) (string, string, error) {
	// Phase 1: OCSP
	if useOcsp && len(cert.OCSPServer) > 0 {
		ocspEp := cert.OCSPServer[0]
		logger.Info("Attempting OCSP query against %s", ocspEp)
		
		reqDER, err := ocsp.CreateRequest(cert, issuer, nil)
		if err == nil {
			httpReq, err := http.NewRequest("POST", ocspEp, bytes.NewBuffer(reqDER))
			if err == nil {
				httpReq.Header.Set("Content-Type", "application/ocsp-request")
				resp, err := http.DefaultClient.Do(httpReq)
				if err == nil {
					defer resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						respBytes, _ := io.ReadAll(resp.Body)
						ocspResp, err := ocsp.ParseResponseForCert(respBytes, cert, issuer)
						// Valid response handling!
						if err == nil {
							if err := ocspResp.CheckSignatureFrom(issuer); err == nil {
								if ocspResp.Status == ocsp.Good {
									return "good", "", nil
								} else if ocspResp.Status == ocsp.Revoked {
									return "revoked", fmt.Sprintf("OCSP Status: Revoked at %s (Reason: %d)", ocspResp.RevokedAt, ocspResp.RevocationReason), nil
								}
							}
						}
					}
				}
			}
		}
		logger.Warning("OCSP query failed. Proceeding with CRL Fallback mechanism natively.")
	}

	// Phase 2: CRL Fallback
	crlTargets := cert.CRLDistributionPoints
	if crlOverride != "" {
		crlTargets = []string{crlOverride}
	}

	for _, cdp := range crlTargets {
		logger.Info("Attempting CRL fetch against %s", cdp)
		crlBytes, err := fetchResourceBytes(cdp)
		if err != nil {
			continue
		}

		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			// Some endpoints serve PEM while parse expects DER natively; try PEM decode
			var derBytes []byte
			if block, _ := pem.Decode(crlBytes); block != nil && block.Type == "X509 CRL" {
				derBytes = block.Bytes
			} else {
				continue
			}
			crl, err = x509.ParseRevocationList(derBytes)
			if err != nil {
				continue
			}
		}

		if err := crl.CheckSignatureFrom(issuer); err != nil {
			logger.Warning("CRL signature check completely failed")
			continue
		}

		// Enforce validity parsing
		for _, rc := range crl.RevokedCertificates {
			if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return "revoked", "Found definitively matched inside active CRL registry bounds", nil
			}
		}

		return "good", "", nil
	}

	return "unknown", "", fmt.Errorf("unable to resolve definitive network revocation logic (all endpoints timed out / missing)")
}

func fetchResourceBytes(target string) ([]byte, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		resp, err := http.Get(target)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("bad network status %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}

	// Attempt local file binding explicitly for CRL
	path := target
	if strings.HasPrefix(target, "file://") {
		u, err := url.Parse(target)
		if err == nil {
			path = u.Path
		}
	}
	return os.ReadFile(path)
}
