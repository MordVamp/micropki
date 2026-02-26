package logger

import (
	"fmt"
	"log"
	"os"
	"time"
)

var (
	logFile   *os.File
	logger    *log.Logger
	useStderr = true
)

// Init sets up logging: if filePath is empty, logs go to stderr; otherwise to the file.
func Init(filePath string) error {
	if filePath == "" {
		logger = log.New(os.Stderr, "", 0)
		useStderr = true
		return nil
	}

	var err error
	logFile, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	logger = log.New(logFile, "", 0)
	useStderr = false
	return nil
}

// Close closes the log file if open.
func Close() {
	if logFile != nil {
		logFile.Close()
	}
}

// logEntry formats a log line with timestamp and level.
func logEntry(level, format string, args ...interface{}) {
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [%s] %s", timestamp, level, msg)
	if useStderr {
		// Also print to stderr if we are not already writing there
		fmt.Fprintln(os.Stderr, line)
	} else {
		logger.Println(line)
	}
}

// Info logs at INFO level.
func Info(format string, args ...interface{}) {
	logEntry("INFO", format, args...)
}

// Warning logs at WARNING level.
func Warning(format string, args ...interface{}) {
	logEntry("WARNING", format, args...)
}

// Error logs at ERROR level.
func Error(format string, args ...interface{}) {
	logEntry("ERROR", format, args...)
}
