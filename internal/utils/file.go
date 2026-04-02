package utils

import (
	"fmt"
	"os"

	"micropki/internal/logger"
)

// SafeWriteFile writes data to a file. If force is false and the file exists, it returns an error.
func SafeWriteFile(path string, data []byte, perm os.FileMode, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			logger.Error("File %s already exists. Use --force to overwrite.", path)
			return fmt.Errorf("file %s already exists", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return os.WriteFile(path, data, perm)
}
