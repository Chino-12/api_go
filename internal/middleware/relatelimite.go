package middleware

import (
	"log"
	"net"
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

// IPRateLimiter maintains rate limiters for individual IP addresses
type IPRateLimiter struct {
	limiters sync.Map   // Thread-safe map to store rate limiters per IP
	rate     rate.Limit // Rate limit (requests per second)
	burst    int        // Maximum burst size (additional allowed requests)
}

// NewIPRateLimiter creates a new rate limiter instance configured for 5 requests per 30 seconds
func NewIPRateLimiter() *IPRateLimiter {
	return &IPRateLimiter{
		rate:  rate.Limit(5.0 / 30.0), // 5 requests every 30 seconds (0.166... req/sec)
		burst: 0,
	}
}

// GetLimiter retrieves or creates a rate limiter for the given IP address
func (l *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	// Check if limiter already exists for this IP
	limiter, exists := l.limiters.Load(ip)
	if !exists {
		// Create new limiter if none exists
		newLimiter := rate.NewLimiter(l.rate, l.burst)
		l.limiters.Store(ip, newLimiter)
		return newLimiter
	}
	return limiter.(*rate.Limiter)
}

// Global limiter instance
var ipLimiter = NewIPRateLimiter()

// getClientIP extracts the client IP address from the request

func getClientIP(r *http.Request) string {
	// Check for proxy-forwarded IP first
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	// Fall back to direct connection IP (removing port if present)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// RateLimitMiddleware is an HTTP middleware that enforces rate limiting per IP
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		limiter := ipLimiter.GetLimiter(ip)

		// Check if request is allowed
		if !limiter.Allow() {
			log.Printf("⛔ Rate limit exceeded for IP: %s\n", ip)
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		log.Printf("✅ Request allowed from IP: %s\n", ip)
		next.ServeHTTP(w, r)
	})
}
