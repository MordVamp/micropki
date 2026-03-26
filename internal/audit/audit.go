package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	auditDir   string = "./pki/audit"
	auditLog   string
	chainFile  string
	ctLog      string
	mu         sync.Mutex
	isInit     bool
	zeroHash   string = "0000000000000000000000000000000000000000000000000000000000000000"
)

type Integrity struct {
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Operation string                 `json:"operation"`
	Status    string                 `json:"status"`
	Message   string                 `json:"message"`
	Metadata  map[string]interface{} `json:"metadata"`
	Integrity Integrity              `json:"integrity"`
}

// Init initializes the audit system, setting up directories and files.
func Init(baseDir string) error {
	mu.Lock()
	defer mu.Unlock()
	auditDir = filepath.Join(baseDir, "audit")
	auditLog = filepath.Join(auditDir, "audit.log")
	chainFile = filepath.Join(auditDir, "chain.dat")
	ctLog = filepath.Join(auditDir, "ct.log")

	if err := os.MkdirAll(auditDir, 0755); err != nil {
		return err
	}

	// Initialize chain.dat if it doesn't exist
	if _, err := os.Stat(chainFile); os.IsNotExist(err) {
		if err := os.WriteFile(chainFile, []byte(zeroHash), 0644); err != nil {
			return err
		}
	}
	
	// Create audit.log if missing
	if _, err := os.Stat(auditLog); os.IsNotExist(err) {
		f, err := os.Create(auditLog)
		if err != nil {
			return err
		}
		f.Close()
	}

	// Create ct.log if missing
	if _, err := os.Stat(ctLog); os.IsNotExist(err) {
		f, err := os.Create(ctLog)
		if err != nil {
			return err
		}
		f.Close()
	}

	isInit = true
	return nil
}

// LogEvent logs a security-sensitive event with hash chain integrity.
func LogEvent(level, operation, status, message string, metadata map[string]interface{}) error {
	mu.Lock()
	defer mu.Unlock()

	if !isInit {
		// Attempt to init with default if not explicitly initialized
		mu.Unlock()
		_ = Init("./pki")
		mu.Lock()
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	// Get prev hash
	prevBytes, err := os.ReadFile(chainFile)
	if err != nil {
		return fmt.Errorf("could not read chain file: %v", err)
	}
	prevHash := string(prevBytes)

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		Level:     level,
		Operation: operation,
		Status:    status,
		Message:   message,
		Metadata:  metadata,
		Integrity: Integrity{
			PrevHash: prevHash,
			Hash:     "", // calculate later
		},
	}

	// compute hash on canonical JSON (sorted keys, no extra space) of the entry excluding integrity.hash
	canonicalMap := map[string]interface{}{
		"timestamp": entry.Timestamp,
		"level":     entry.Level,
		"operation": entry.Operation,
		"status":    entry.Status,
		"message":   entry.Message,
		"metadata":  entry.Metadata,
		"integrity": map[string]interface{}{
			"prev_hash": entry.Integrity.PrevHash,
		},
	}

	raw, err := json.Marshal(canonicalMap)
	if err != nil {
		return err
	}

	h := sha256.Sum256(raw)
	entryHash := hex.EncodeToString(h[:])
	entry.Integrity.Hash = entryHash

	finalJSON, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	finalJSON = append(finalJSON, '\n')

	// Append to log
	f, err := os.OpenFile(auditLog, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(finalJSON); err != nil {
		return err
	}

	// Update chain
	if err := os.WriteFile(chainFile, []byte(entryHash), 0644); err != nil {
		return err
	}

	return nil
}
