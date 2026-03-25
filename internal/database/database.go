package database

import (
	"database/sql"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"micropki/internal/logger"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

type CertificateRecord struct {
	ID               int64
	SerialHex        string
	Subject          string
	Issuer           string
	NotBefore        string
	NotAfter         string
	CertPEM          string
	Status           string
	RevocationReason *string
	RevocationDate   *string
	CreatedAt        string
}

// InitDB initializes the SQLite database connection and sets up the schema.
func InitDB(dbPath string) error {
	logger.Info("Initializing database at %s", dbPath)
	
	// Ensure directory exists
	// The caller should handle the directory creation or we can do it here. Let's not assume directory existence.
	dbUri := fmt.Sprintf("file:%s?_journal=WAL&_busy_timeout=5000", filepath.ToSlash(dbPath))

	var err error
	DB, err = sql.Open("sqlite3", dbUri)
	if err != nil {
		logger.Error("Failed to open database: %v", err)
		return fmt.Errorf("open db: %w", err)
	}

	// Ping the DB to confirm connection
	if err := DB.Ping(); err != nil {
		logger.Error("Failed to ping database: %v", err)
		return fmt.Errorf("ping db: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		serial_hex TEXT UNIQUE NOT NULL,
		subject TEXT NOT NULL,
		issuer TEXT NOT NULL,
		not_before TEXT NOT NULL,
		not_after TEXT NOT NULL,
		cert_pem TEXT NOT NULL,
		status TEXT NOT NULL,
		revocation_reason TEXT,
		revocation_date TEXT,
		created_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_serial_hex ON certificates(serial_hex);
	CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
	`

	if _, err := DB.Exec(schema); err != nil {
		logger.Error("Failed to execute database schema: %v", err)
		return fmt.Errorf("exec schema: %w", err)
	}

	logger.Info("Database initialized successfully")
	return nil
}

// InsertCertificate adds a new certificate to the database.
func InsertCertificate(serial *big.Int, subject, issuer string, notBefore, notAfter time.Time, certPEM []byte) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	serialHex := fmt.Sprintf("%x", serial)
	now := time.Now().UTC().Format(time.RFC3339)

	logger.Info("Inserting certificate (serial: %s, subject: %s)", serialHex, subject)

	query := `
	INSERT INTO certificates (
		serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := DB.Exec(
		query,
		serialHex,
		subject,
		issuer,
		notBefore.UTC().Format(time.RFC3339),
		notAfter.UTC().Format(time.RFC3339),
		string(certPEM),
		"valid",
		now,
	)

	if err != nil {
		logger.Error("Failed to insert certificate: %v", err)
		// Check for constraint violation for clear error message
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("duplicate serial number: %s", serialHex)
		}
		return fmt.Errorf("insert cert: %w", err)
	}

	logger.Info("Certificate successfully inserted into database")
	return nil
}

// GetCertificateBySerial retrieves a certificate by its hex serial number.
func GetCertificateBySerial(serialHex string) (*CertificateRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	serialHex = strings.ToLower(serialHex) // ensure case-insensitivity visually if needed
	query := `
	SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem, status, revocation_reason, revocation_date, created_at
	FROM certificates
	WHERE LOWER(serial_hex) = ?
	`

	row := DB.QueryRow(query, serialHex)

	var rec CertificateRecord
	err := row.Scan(
		&rec.ID,
		&rec.SerialHex,
		&rec.Subject,
		&rec.Issuer,
		&rec.NotBefore,
		&rec.NotAfter,
		&rec.CertPEM,
		&rec.Status,
		&rec.RevocationReason,
		&rec.RevocationDate,
		&rec.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // not found
		}
		logger.Error("Database error during certificate retrieval: %v", err)
		return nil, fmt.Errorf("get cert by serial: %w", err)
	}

	return &rec, nil
}

// ListCertificates retrieves certificates optionally filtered by status.
func ListCertificates(status string) ([]CertificateRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var rows *sql.Rows
	var err error

	if status != "" {
		query := `
		SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem, status, revocation_reason, revocation_date, created_at
		FROM certificates
		WHERE LOWER(status) = ?
		ORDER BY created_at DESC
		`
		rows, err = DB.Query(query, strings.ToLower(status))
	} else {
		query := `
		SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem, status, revocation_reason, revocation_date, created_at
		FROM certificates
		ORDER BY created_at DESC
		`
		rows, err = DB.Query(query)
	}

	if err != nil {
		logger.Error("Failed to query certificates list: %v", err)
		return nil, fmt.Errorf("list certs: %w", err)
	}
	defer rows.Close()

	var records []CertificateRecord
	for rows.Next() {
		var rec CertificateRecord
		err := rows.Scan(
			&rec.ID,
			&rec.SerialHex,
			&rec.Subject,
			&rec.Issuer,
			&rec.NotBefore,
			&rec.NotAfter,
			&rec.CertPEM,
			&rec.Status,
			&rec.RevocationReason,
			&rec.RevocationDate,
			&rec.CreatedAt,
		)
		if err != nil {
			logger.Error("Failed to scan certificate record: %v", err)
			return nil, fmt.Errorf("scan cert list: %w", err)
		}
		records = append(records, rec)
	}

	return records, nil
}

// CheckSerialExists returns true if a serial number already exists.
func CheckSerialExists(serialHex string) (bool, error) {
	if DB == nil {
		return false, fmt.Errorf("database not initialized")
	}

	var count int
	query := `SELECT COUNT(*) FROM certificates WHERE LOWER(serial_hex) = ?`
	err := DB.QueryRow(query, strings.ToLower(serialHex)).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CreateDBIfNotExists is a helper for startup
func CreateDBIfNotExists(dbPath string) error {
	dir := filepath.Dir(dbPath)
	return InitDB(dbPath)
}
