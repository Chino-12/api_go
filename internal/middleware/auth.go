package middleware

import (
	"net/http"
	"strings"

	"api-go/internal/database"

	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware verifies if the request contains a valid JWT token
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the Authorization header from the request
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusUnauthorized, "Authorization token required")
			return
		}

		// Extract the token from the "Bearer <token>" format
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader { // No Bearer prefix found
			respondWithError(w, http.StatusUnauthorized, "Invalid token format. Use Bearer <token>")
			return
		}

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return database.JwtSecret, nil // Use the JWT secret from the database package
		})

		// Check if the token is valid
		if err != nil {
			respondWithError(w, http.StatusUnauthorized, "Invalid token: "+err.Error())
			return
		}

		if !token.Valid {
			respondWithError(w, http.StatusUnauthorized, "Token is not valid")
			return
		}

		// If the token is valid, call the next handler in the chain
		next.ServeHTTP(w, r)
	})
}
