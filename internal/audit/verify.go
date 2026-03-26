package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Verify(logFile, chainFileStr string) error {
	if logFile == "" {
		logFile = auditLog
	}
	if chainFileStr == "" {
		chainFileStr = filepath.Join(filepath.Dir(logFile), "chain.dat")
	}

	f, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // empty but valid
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	expectedPrevHash := zeroHash

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return fmt.Errorf("line %d: invalid JSON - %v", lineNum, err)
		}

		if entry.Integrity.PrevHash != expectedPrevHash {
			return fmt.Errorf("line %d: prev_hash mismatch.\nExpected: %s\nGot:      %s", lineNum, expectedPrevHash, entry.Integrity.PrevHash)
		}

		// Recompute hash
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
			return fmt.Errorf("line %d: failed to marshal canonical JSON", lineNum)
		}

		h := sha256.Sum256(raw)
		computedHash := hex.EncodeToString(h[:])

		if computedHash != entry.Integrity.Hash {
			return fmt.Errorf("line %d: hash mismatch.\nComputed: %s\nStored:   %s", lineNum, computedHash, entry.Integrity.Hash)
		}

		expectedPrevHash = computedHash
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Compare with chainFile
	if c, err := os.ReadFile(chainFileStr); err == nil {
		storedChain := strings.TrimSpace(string(c))
		if storedChain != expectedPrevHash && storedChain != zeroHash {
			return fmt.Errorf("chain file mismatch:\nLog ends with: %s\nChain.dat has: %s", expectedPrevHash, storedChain)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("could not read chain file: %v", err)
	}

	return nil
}
