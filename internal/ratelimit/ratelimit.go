package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	visitors      = make(map[string]*rate.Limiter)
	mu            sync.Mutex
	globalLimiter *rate.Limiter
)

func init() {
	// Global token bucket for the root of the hierarchy
	globalLimiter = rate.NewLimiter(rate.Limit(1000), 200)
}

func getVisitor(ip string, rLimit float64, rBurst int) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := visitors[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(rLimit), rBurst)
		visitors[ip] = limiter
	}
	return limiter
}

// HTBListener wraps a net.Listener to provide Hierarchical Token Bucket rate limiting on TCP Accept.
type HTBListener struct {
	net.Listener
	Limit float64
	Burst int
}

func (l *HTBListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		if l.Limit <= 0 {
			return conn, nil
		}

		// Apply global limit (hierarchy root)
		if !globalLimiter.Allow() {
			conn.Close()
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Apply per-IP limit (hierarchy leaf)
		ip := strings.Split(conn.RemoteAddr().String(), ":")[0]
		limiter := getVisitor(ip, l.Limit, l.Burst)

		if !limiter.Allow() {
			conn.Close() // Reject connection if rate limit exceeded
			// Add a tiny delay to prevent busy looping on high DoS
			time.Sleep(10 * time.Millisecond)
			continue
		}

		return conn, nil
	}
}

// LimitListener wraps a standard listener with HTB TCP rate limiting.
func LimitListener(l net.Listener, limit float64, burst int) net.Listener {
	if limit <= 0 {
		return l
	}
	return &HTBListener{
		Listener: l,
		Limit:    limit,
		Burst:    burst,
	}
}

// Middleware returns an HTTP middleware that limits requests per IP address.
// Retained for backward compatibility if needed.
func Middleware(limit float64, burst int, next http.Handler) http.Handler {
	if limit <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Split(r.RemoteAddr, ":")[0]

		// Global
		if !globalLimiter.Allow() {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "Too Many Requests (Global)", http.StatusTooManyRequests)
			return
		}

		limiter := getVisitor(ip, limit, burst)
		if !limiter.Allow() {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
