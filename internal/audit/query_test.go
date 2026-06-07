package audit

import (
	"testing"
)

func TestQuery(t *testing.T) {
	dir := t.TempDir()
	Init(dir)
	defer Close()
	
	LogEvent("INFO", "cert_issue", "success", "issued cert", map[string]interface{}{"serial": "1234"})
	LogEvent("INFO", "cert_revoke", "success", "revoked cert", map[string]interface{}{"serial": "1234"})

	opts := QueryOptions{
		Operation: "cert_issue",
	}

	results, err := Query(auditLog, opts)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 result, got %d", len(results))
	}
	
	optsSerial := QueryOptions{
		Serial: "1234",
	}
	resultsSer, _ := Query(auditLog, optsSerial)
	if len(resultsSer) != 2 {
		t.Errorf("Expected 2 results by serial, got %d", len(resultsSer))
	}

	resNone, err := Query("nonexistent.log", opts)
	if err != nil {
		t.Error("Expected nil error for nonexistent file (returns nil, nil)")
	}
	if resNone != nil {
		t.Error("Expected nil results for nonexistent file")
	}
}
