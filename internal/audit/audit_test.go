package audit

import (
	"testing"
)

func TestAuditLogEvent(t *testing.T) {
	testDir := t.TempDir()

	// Reset package state to ensure clean Init
	isInit = false
	auditLogWriter = nil

	err := Init(testDir)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = LogEvent("INFO", "test_op", "success", "msg", nil)
	if err != nil {
		t.Fatalf("LogEvent failed: %v", err)
	}

	err = Verify(testDir+"/audit/audit.log", testDir+"/audit/chain.dat")
	if err != nil {
		t.Errorf("Verify returned error: %v", err)
	}

	// Close the lumberjack writer so t.TempDir() cleanup can remove files
	if auditLogWriter != nil {
		auditLogWriter.Close()
	}
}

func TestCTLog(t *testing.T) {
	testDir := t.TempDir()

	// Reset package state to ensure clean Init
	isInit = false
	auditLogWriter = nil

	Init(testDir)

	AppendCTLog("1234", "CN=Test", "abcd", "CN=Issuer")
}
