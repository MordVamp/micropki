package ratelimit

import (
	"net/http"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

var (
	visitors = make(map[string]*rate.Limiter)
	mu       sync.Mutex
)

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

// Middleware returns an HTTP middleware that limits requests per IP address.
func Middleware(limit float64, burst int, next http.Handler) http.Handler {
	if limit <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Split(r.RemoteAddr, ":")[0]
		limiter := getVisitor(ip, limit, burst)
		if !limiter.Allow() {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
