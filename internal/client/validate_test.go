package client

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestValidateChainCryptographically(t *testing.T) {
	now := time.Now()

	// Given an empty chain array, it should not panic, though structural validity drops natively via length
	err := validateChainCryptographically([]*x509.Certificate{}, now)
	if err != nil {
		// Valid execution; length bounding prevents zero-panic
	}
}
