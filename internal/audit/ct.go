package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"micropki/internal/logger"
)

var (
	ctLogMutex sync.Mutex
	ctLogDir   string = "./pki/audit"
)

// AppendCTLog appends an issuance entry to the local Certificate Transparency simulation log.
func AppendCTLog(serialHex, subject, fingerprint, issuer string) {
	ctLogMutex.Lock()
	defer ctLogMutex.Unlock()

	if err := os.MkdirAll(ctLogDir, 0700); err != nil {
		logger.Error("Failed to create CT log directory: %v", err)
		return
	}

	logPath := filepath.Join(ctLogDir, "ct.log")
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Error("Failed to open CT log file: %v", err)
		return
	}
	defer file.Close()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	entry := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\n", timestamp, serialHex, subject, fingerprint, issuer)

	if _, err := file.WriteString(entry); err != nil {
		logger.Error("Failed to write to CT log: %v", err)
	}
}
