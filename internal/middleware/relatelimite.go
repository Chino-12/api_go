package middleware

import (
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

// IPRateLimiter maintains rate limiters for individual IP addresses
type IPRateLimiter struct {
	ips map[string]*rate.Limiter // Map of IP addresses to their respective limiters
	mu  *sync.RWMutex            // Mutex to ensure thread-safe access to the map
	r   rate.Limit               // Requests per second limit
	b   int                      // Burst size (maximum allowed spikes)
}

// NewIPRateLimiter creates a new instance of IPRateLimiter
// Parameters:
//   - r: rate limit (requests per second)
//   - b: burst size (maximum allowed spikes)
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		mu:  &sync.RWMutex{},
		r:   r,
		b:   b,
	}
}

// AddIP creates a new rate limiter for an IP address and adds it to the map
func (i *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.r, i.b)
	i.ips[ip] = limiter

	return limiter
}

// GetLimiter returns the rate limiter for the given IP address
// If no limiter exists, it creates a new one
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.RLock()
	limiter, exists := i.ips[ip]
	i.mu.RUnlock()

	if !exists {
		return i.AddIP(ip)
	}

	return limiter
}

// RateLimitMiddleware is an HTTP middleware that enforces rate limiting
// It limits each IP to 5 requests per second with a burst of 1
func RateLimitMiddleware(next http.Handler) http.Handler {
	// Initialize rate limiter with 5 requests/sec and burst of 1
	limiter := NewIPRateLimiter(5, 1)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP address
		ip := r.RemoteAddr

		// Get or create rate limiter for this IP
		limiter := limiter.GetLimiter(ip)

		// Check if request is allowed
		if !limiter.Allow() {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		// Proceed to next handler if rate limit is not exceeded
		next.ServeHTTP(w, r)
	})
}
