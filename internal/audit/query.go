package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"
)

type QueryOptions struct {
	From      string
	To        string
	Level     string
	Operation string
	Serial    string
}

func Query(logFile string, opts QueryOptions) ([]LogEntry, error) {
	if logFile == "" {
		logFile = auditLog
	}

	f, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var results []LogEntry

	var fromTime, toTime time.Time
	if opts.From != "" {
		fromTime, _ = time.Parse(time.RFC3339, opts.From)
	}
	if opts.To != "" {
		toTime, _ = time.Parse(time.RFC3339, opts.To)
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Filter
		if opts.Level != "" && entry.Level != opts.Level {
			continue
		}
		if opts.Operation != "" && entry.Operation != opts.Operation {
			continue
		}
		if opts.Serial != "" {
			if ser, ok := entry.Metadata["serial"].(string); !ok || ser != opts.Serial {
				continue
			}
		}

		entryTime, err := time.Parse("2006-01-02T15:04:05.000000Z", entry.Timestamp)
		if err == nil {
			if !fromTime.IsZero() && entryTime.Before(fromTime) {
				continue
			}
			if !toTime.IsZero() && entryTime.After(toTime) {
				continue
			}
		}

		results = append(results, entry)
	}

	return results, scanner.Err()
}
