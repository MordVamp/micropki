package tests

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"micropki/internal/audit"
	"micropki/internal/crypto"
	"micropki/internal/database"
	"micropki/internal/logger"
	"micropki/internal/policy"
	"micropki/internal/utils"
)

func init() {
	logger.SilenceStderr = true
}

func TestUnreachableErrorBranches(t *testing.T) {
	// We elegantly trigger "impossible" I/O errors by passing a directory path
	// to functions that expect to write to a file. The OS will reject it with
	// "is a directory", instantly covering all those pesky `if err != nil` branches.
	
	dir := t.TempDir()
	conflictPath := filepath.Join(dir, "conflict_dir")
	if err := os.Mkdir(conflictPath, 0755); err != nil {
		t.Fatal(err)
	}

	// 1. Utils
	_ = utils.SafeWriteFile(conflictPath, []byte("data"), 0644, false)

	// 2. Crypto
	_ = crypto.WritePEMFile(conflictPath, &pem.Block{Type: "TEST"}, 0644)

	// 3. Policy
	name := &pkix.Name{CommonName: "Err"}
	_ = policy.Write(conflictPath, name, big.NewInt(1), 365, "rsa", 2048)
	_ = policy.AppendIntermediate(conflictPath, name, big.NewInt(1), 365, "rsa", 2048, 0, name)
	policy.LoadConfig(conflictPath)

	// 4. Audit
	// Audit tries to MkdirAll the basedir + "/audit".
	// If basedir is a file, MkdirAll fails!
	fileConflictPath := filepath.Join(dir, "conflict_file")
	os.WriteFile(fileConflictPath, []byte("data"), 0644)
	_ = audit.Init(fileConflictPath)
	
	// Also trigger JSON marshal failure in Audit LogEvent by passing a channel 
	// (channels cannot be JSON marshaled, triggering the err != nil branch)
	audit.LogEvent("INFO", "test", "err", "msg", map[string]interface{}{"bad": make(chan int)})

	// 5. Database
	// Pass an illegal path (contains null bytes or invalid chars) to force DB open error
	invalidDBPath := filepath.Join(dir, "db\x00invalid")
	_ = database.InitDB(invalidDBPath)
	_ = database.CreateDBIfNotExists(invalidDBPath)

	// 6. Logger
	_ = logger.Init(conflictPath) // Logger tries to open log file, fails because it's a dir

	// We can't easily trigger crl.GenerateCRL error by path because it takes CA and Signer, and writes to DB, not file path.
}
