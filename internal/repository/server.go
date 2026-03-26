package repository

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"micropki/internal/database"
	"micropki/internal/logger"
	"micropki/internal/ratelimit"
)

// Server holds the repository server state
type Server struct {
	Host       string
	Port       int
	DBPath     string
	CertDir    string
	CACertPath string
	CAKeyPath  string
	CAPassPath string
	RateLimit  int
	RateBurst  int
}

// loggingMiddleware logs the incoming HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a custom response writer to capture the status code
		lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		
		next.ServeHTTP(lrw, r)
		
		logger.Info("[HTTP] %s %s %s %d %v", r.Method, r.URL.Path, r.RemoteAddr, lrw.status, time.Since(start))
	})
}

// loggingResponseWriter captures the HTTP status code from the response
type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Start runs the HTTP repository server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)

	mux := http.NewServeMux()

	// Endpoints
	mux.HandleFunc("/certificate/", s.handleCertificate)
	mux.HandleFunc("/ca/", s.handleCA)
	mux.HandleFunc("/crl", s.handleCRL)
	mux.HandleFunc("/request-cert", s.handleRequestCert)

	// Apply middleware
	handler := corsMiddleware(loggingMiddleware(mux))
	handler = ratelimit.Middleware(float64(s.RateLimit), s.RateBurst, handler)

	logger.Info("Starting repository server on http://%s", addr)
	
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	return srv.ListenAndServe()
}

// corsMiddleware adds the Access-Control-Allow-Origin header
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// URL format: /certificate/<serial>
	serialHex := strings.TrimPrefix(r.URL.Path, "/certificate/")
	if serialHex == "" {
		http.Error(w, "Serial number required", http.StatusBadRequest)
		return
	}

	certRecord, err := database.GetCertificateBySerial(serialHex)
	if err != nil {
		logger.Error("Database lookup failed for serial %s: %v", serialHex, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if certRecord == nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(certRecord.CertPEM))
}

func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// URL format: /ca/<level>
	level := strings.TrimPrefix(r.URL.Path, "/ca/")
	
	var filename string
	switch level {
	case "root":
		filename = "ca.cert.pem"
	case "intermediate":
		filename = "intermediate.cert.pem"
	default:
		http.Error(w, "Invalid CA level (must be 'root' or 'intermediate')", http.StatusBadRequest)
		return
	}

	certPath := filepath.Join(s.CertDir, filename)
	
	file, err := os.Open(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warning("CA certificate not found on disk: %s", certPath)
			http.Error(w, "CA Certificate not found", http.StatusNotFound)
			return
		}
		logger.Error("Failed to open CA certificate file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, file)
}

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	caLevel := r.URL.Query().Get("ca")
	if caLevel == "" {
		caLevel = "intermediate" // default
	}

	var filename string
	if caLevel == "root" {
		filename = "root.crl.pem"
	} else if caLevel == "intermediate" {
		filename = "intermediate.crl.pem"
	} else {
		http.Error(w, "Invalid CA parameter", http.StatusBadRequest)
		return
	}

	crlPath := filepath.Join(filepath.Dir(s.CertDir), "crl", filename)
	
	file, err := os.Open(crlPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warning("CRL file not found on disk: %s", crlPath)
			http.Error(w, "CRL not found", http.StatusNotFound)
			return
		}
		logger.Error("Failed to open CRL file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, file)
}

func (s *Server) handleRequestCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Simple Pre-Shared Key for Sprint 6 Demo Security
	// WARNING: Insecure for Production. Hardcoding keys is a massive vulnerability.
	if r.Header.Get("X-API-Key") != "changeme" {
		http.Error(w, "Unauthorized (requires X-API-Key: changeme)", http.StatusUnauthorized)
		return
	}

	templateName := r.URL.Query().Get("template")
	if templateName == "" {
		http.Error(w, "template query parameter is required", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	tmpFile, err := os.CreateTemp("", "csr-*.pem")
	if err != nil {
		http.Error(w, "internal config error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(body); err != nil {
		http.Error(w, "internal write error", http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	exePath, err := os.Executable()
	if err != nil {
		http.Error(w, "internal exe resolution error", http.StatusInternalServerError)
		return
	}

	outDir, err := os.MkdirTemp("", "out-*")
	if err != nil {
		http.Error(w, "internal mkdir error", http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(outDir)

	cmd := exec.Command(exePath, "ca", "issue-cert",
		"--csr", tmpFile.Name(),
		"--template", templateName,
		"--ca-cert", s.CACertPath,
		"--ca-key", s.CAKeyPath,
		"--ca-pass-file", s.CAPassPath,
		"--subject", "CN=Dynamic", // natively overridden by CSR internal fields!
		"--out-dir", outDir,
		"--db-path", s.DBPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Issue cert via execution failed: %s %v", string(output), err)
		http.Error(w, "failed to dynamically issue certificate", http.StatusInternalServerError)
		return
	}

	files, err := os.ReadDir(outDir)
	if err != nil {
		http.Error(w, "internal stat error", http.StatusInternalServerError)
		return
	}

	var certPath string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".cert.pem") {
			certPath = filepath.Join(outDir, f.Name())
			break
		}
	}

	if certPath == "" {
		http.Error(w, "certificate not materialized locally", http.StatusInternalServerError)
		return
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		http.Error(w, "internal read error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusCreated)
	w.Write(certPEM)
}

