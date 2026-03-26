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

	CREATE TABLE IF NOT EXISTS crl_metadata (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ca_subject TEXT NOT NULL,
		crl_number INTEGER NOT NULL,
		last_generated TEXT NOT NULL,
		next_update TEXT NOT NULL,
		crl_path TEXT NOT NULL
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject);

	CREATE TABLE IF NOT EXISTS compromised_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		public_key_hash TEXT UNIQUE NOT NULL,
		certificate_serial TEXT NOT NULL,
		compromise_date TEXT NOT NULL,
		compromise_reason TEXT NOT NULL,
		FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_hex)
	);
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
	return InitDB(dbPath)
}

type CRLMetadata struct {
	ID            int64
	CASubject     string
	CRLNumber     int64
	LastGenerated string
	NextUpdate    string
	CRLPath       string
}

// RevokeCertificate marks a certificate as revoked. 
func RevokeCertificate(serialHex string, reason string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	serialHex = strings.ToLower(serialHex)
	now := time.Now().UTC().Format(time.RFC3339)

	query := `
	UPDATE certificates
	SET status = 'revoked', revocation_reason = ?, revocation_date = ?
	WHERE LOWER(serial_hex) = ? AND status = 'valid'
	`

	res, err := DB.Exec(query, reason, now, serialHex)
	if err != nil {
		logger.Error("Database error during revocation: %v", err)
		return fmt.Errorf("revoke cert: %w", err)
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("certificate %s not found or already revoked/expired", serialHex)
	}

	logger.Info("Certificate %s revoked successfully (reason: %s)", serialHex, reason)
	return nil
}

// GetRevokedCertificates fetches all revoked certificates for a specific CA issuer.
func GetRevokedCertificates(issuerDN string) ([]CertificateRecord, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	query := `
	SELECT id, serial_hex, subject, issuer, not_before, not_after, cert_pem, status, revocation_reason, revocation_date, created_at
	FROM certificates
	WHERE LOWER(status) = 'revoked' AND issuer = ?
	`
	rows, err := DB.Query(query, issuerDN)
	if err != nil {
		return nil, fmt.Errorf("get revoked certs: %w", err)
	}
	defer rows.Close()

	var records []CertificateRecord
	for rows.Next() {
		var rec CertificateRecord
		if err := rows.Scan(&rec.ID, &rec.SerialHex, &rec.Subject, &rec.Issuer, &rec.NotBefore, &rec.NotAfter, &rec.CertPEM, &rec.Status, &rec.RevocationReason, &rec.RevocationDate, &rec.CreatedAt); err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// GetCRLMetadata retrieves the CRL metadata for a CA.
func GetCRLMetadata(caSubject string) (*CRLMetadata, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	query := `SELECT id, ca_subject, crl_number, last_generated, next_update, crl_path FROM crl_metadata WHERE ca_subject = ?`
	row := DB.QueryRow(query, caSubject)

	var meta CRLMetadata
	err := row.Scan(&meta.ID, &meta.CASubject, &meta.CRLNumber, &meta.LastGenerated, &meta.NextUpdate, &meta.CRLPath)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // not found
		}
		return nil, err
	}
	return &meta, nil
}

// UpdateCRLMetadata inserts or updates CRL metadata.
func UpdateCRLMetadata(meta CRLMetadata) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	// upsert
	query := `
	INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
	VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(ca_subject) DO UPDATE SET
		crl_number=excluded.crl_number,
		last_generated=excluded.last_generated,
		next_update=excluded.next_update,
		crl_path=excluded.crl_path
	`
	_, err := DB.Exec(query, meta.CASubject, meta.CRLNumber, meta.LastGenerated, meta.NextUpdate, meta.CRLPath)
	return err
}

// MarkKeyCompromised marks a public key hash as compromised.
func MarkKeyCompromised(pubKeyHash, serialHex, date, reason string) error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}

	query := `
	INSERT INTO compromised_keys (public_key_hash, certificate_serial, compromise_date, compromise_reason)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(public_key_hash) DO NOTHING
	`
	_, err := DB.Exec(query, strings.ToLower(pubKeyHash), strings.ToLower(serialHex), date, reason)
	return err
}

// IsKeyCompromised checks if a public key hash is compromised.
func IsKeyCompromised(pubKeyHash string) (bool, error) {
	if DB == nil {
		return false, fmt.Errorf("database not initialized")
	}

	var count int
	query := `SELECT COUNT(*) FROM compromised_keys WHERE LOWER(public_key_hash) = ?`
	err := DB.QueryRow(query, strings.ToLower(pubKeyHash)).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
