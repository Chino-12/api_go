package middleware

import (
	"api-go/internal/logger"
	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"
)

// ErrorHandler catches panics and returns a JSON error response
func ErrorHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Defer a function to recover from panics
		defer func() {
			if err := recover(); err != nil {
				// Log the panic with structured logging
				logger.Log.WithFields(logrus.Fields{
					"endpoint": r.URL.Path,
					"method":   r.Method,
					"error":    err,
				}).Error("panic occurred")

				// Respond with a JSON error message
				respondWithError(w, http.StatusInternalServerError, "Internal server error")
			}
		}()
		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

// respondWithError sends a JSON response with an error message
func respondWithError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json") // Set the response content type to JSON
	w.WriteHeader(status)                              // Set the HTTP status code
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"message": message,
	})
}
