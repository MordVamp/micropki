package repository

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"micropki/internal/database"
	"micropki/internal/logger"
)

// Server holds the repository server state
type Server struct {
	Host    string
	Port    int
	DBPath  string
	CertDir string
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

	// Apply middleware
	handler := corsMiddleware(loggingMiddleware(mux))

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

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("501 Not Implemented: CRL generation not yet implemented"))
}
