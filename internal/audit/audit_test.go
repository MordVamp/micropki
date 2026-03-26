package audit

import (
	"os"
	"testing"
)

func TestAuditLogEvent(t *testing.T) {
	testDir := "./test_pki"
	defer os.RemoveAll(testDir)
	
	err := Init(testDir)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = LogEvent("INFO", "test_op", "success", "msg", nil)
	if err != nil {
		t.Fatalf("LogEvent failed: %v", err)
	}
	
	err = Verify(testDir + "/audit/audit.log", testDir + "/audit/chain.dat")
	if err != nil {
		t.Errorf("Verify returned error: %v", err)
	}
}

func TestCTLog(t *testing.T) {
	testDir := "./test_pki"
	defer os.RemoveAll(testDir)
	
	Init(testDir)
	
	AppendCTLog("1234", "CN=Test", "abcd", "CN=Issuer")
	// The CT log defaults to ./pki/audit if not overridden
	defer os.RemoveAll("./pki/audit")
}
