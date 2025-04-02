package main

import (
	"log"
	"net/http"

	"api-go/internal/database"
	"api-go/internal/handlers"
	"api-go/internal/middleware"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {
	// Initialize database connection
	database.Connect()

	// Create a new router using gorilla/mux
	r := mux.NewRouter()

	// Register middleware
	r.Use(middleware.ErrorHandler)        // Custom error handling middleware
	r.Use(middleware.RateLimitMiddleware) // Rate limiting middleware (5 requests/sec per IP)

	// Public routes (no authentication required)
	r.HandleFunc("/login", handlers.Login).Methods("POST")
	r.HandleFunc("/register", handlers.Register).Methods("POST")

	// Configure CORS (Cross-Origin Resource Sharing)
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:4200"}, // Allow frontend origin
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true, // Allow cookies and credentials
	})

	// Start the HTTP server with CORS and router
	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", c.Handler(r)))
}
