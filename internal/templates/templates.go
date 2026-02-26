package templates

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

type TemplateType int

const (
	Server TemplateType = iota
	Client
	CodeSigning
)

func (t TemplateType) String() string {
	return []string{"server", "client", "code_signing"}[t]
}

// ParseTemplate converts a string to TemplateType.
func ParseTemplate(s string) (TemplateType, error) {
	switch strings.ToLower(s) {
	case "server":
		return Server, nil
	case "client":
		return Client, nil
	case "code_signing":
		return CodeSigning, nil
	default:
		return 0, fmt.Errorf("unknown template: %s", s)
	}
}

// BuildTemplate creates a certificate template based on the given type, subject, SANs, and validity.
// It sets appropriate KeyUsage, ExtendedKeyUsage, and BasicConstraints.
func BuildTemplate(tmplType TemplateType, subject *pkix.Name, sans []string, validityDays int, serial *big.Int) (*x509.Certificate, error) {
	now := time.Now().UTC()
	template := &x509.Certificate{
		Version:               3,
		SerialNumber:          serial,
		Subject:               *subject,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, validityDays),
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Parse SANs
	dnsNames, ipAddresses, emailAddresses, uris, err := parseSANs(sans)
	if err != nil {
		return nil, err
	}
	template.DNSNames = dnsNames
	template.IPAddresses = ipAddresses
	template.EmailAddresses = emailAddresses
	template.URIs = uris

	// Validate SAN requirements per template
	switch tmplType {
	case Server:
		if len(dnsNames) == 0 && len(ipAddresses) == 0 {
			return nil, fmt.Errorf("server certificate must have at least one DNS or IP SAN")
		}
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment // RSA typical; for ECC, KeyEncipherment is not needed but harmless.
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case Client:
		// Email addresses are typical but not strictly required; we'll allow any SAN or none?
		// Requirement says "should contain an rfc822Name if provided". We'll just accept whatever.
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case CodeSigning:
		// Ensure no IP SANs? Requirement says "should be limited to DNS or URI". We'll allow DNS and URI.
		if len(ipAddresses) > 0 {
			return nil, fmt.Errorf("code signing certificate cannot have IP SANs")
		}
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}

	return template, nil
}

// parseSANs parses a slice of strings like "dns:example.com", "ip:192.168.1.1", etc.
func parseSANs(sans []string) (dnsNames []string, ipAddresses []net.IP, emailAddresses []string, uris []*url.URL, err error) {
	for _, s := range sans {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return nil, nil, nil, nil, fmt.Errorf("invalid SAN format: %s (expected type:value)", s)
		}
		typ := strings.ToLower(parts[0])
		value := parts[1]
		switch typ {
		case "dns":
			dnsNames = append(dnsNames, value)
		case "ip":
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, nil, nil, nil, fmt.Errorf("invalid IP address: %s", value)
			}
			ipAddresses = append(ipAddresses, ip)
		case "email":
			// Simple validation: must contain @
			if !strings.Contains(value, "@") {
				return nil, nil, nil, nil, fmt.Errorf("invalid email address: %s", value)
			}
			emailAddresses = append(emailAddresses, value)
		case "uri":
			u, err := url.Parse(value)
			if err != nil || u.Scheme == "" {
				return nil, nil, nil, nil, fmt.Errorf("invalid URI: %s", value)
			}
			uris = append(uris, u)
		default:
			return nil, nil, nil, nil, fmt.Errorf("unsupported SAN type: %s", typ)
		}
	}
	return
}
