package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"api-go/docs/utils"
	"api-go/internal/database"
	"api-go/internal/logger"
	"api-go/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Function Error
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}

const (
	TOKEN_EXPIRATION         = 72 * time.Hour
	REFRESH_TOKEN_EXPIRATION = 168 * time.Hour
)

func Login(w http.ResponseWriter, r *http.Request) {
	var user models.User

	// Decode the request body into the user struct
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		logger.Log.WithFields(logrus.Fields{
			"endpoint": "/login",
			"method":   "POST",
			"error":    err.Error(),
		}).Error("Error decoding request body")
		respondWithError(w, http.StatusBadRequest, "Invalid data")
		return
	}

	// Find the user in the database
	var dbUser models.User
	err := database.Coll.FindOne(database.Ctx, bson.M{"email": user.Email}).Decode(&dbUser)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"endpoint": "/login",
			"method":   "POST",
			"email":    user.Email,
			"error":    err.Error(),
		}).Warn("Invalid credentials")
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Verify the password using bcrypt
	if !utils.CheckPasswordHash(user.Password, dbUser.Password) {
		logger.Log.WithFields(logrus.Fields{
			"endpoint": "/login",
			"method":   "POST",
			"email":    user.Email,
		}).Warn("Incorrect password")
		respondWithError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Generate a JWT token with additional user data
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    dbUser.ID.Hex(),
		"email": dbUser.Email,
		"exp":   time.Now().Add(TOKEN_EXPIRATION).Unix(),
		"iat":   time.Now().Unix(),
	})

	tokenString, err := token.SignedString(database.JwtSecret)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"endpoint": "/login",
			"method":   "POST",
			"email":    user.Email,
			"error":    err.Error(),
		}).Error("Error generating JWT token")
		respondWithError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	logger.Log.WithFields(logrus.Fields{
		"endpoint": "/login",
		"method":   "POST",
		"email":    user.Email,
		"userId":   dbUser.ID.Hex(),
	}).Info("Login successful")

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"token":   tokenString,
		"message": "Login successful",
	})
}

func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User

	// Decode the body of the request
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		logger.Log.WithFields(logrus.Fields{
			"endpoint": "/register",
			"method":   "POST",
			"error":    err.Error(),
		}).Error("Error decoding request body")
		respondWithError(w, http.StatusBadRequest, "Invalid data")
		return
	}

	// Set automatic fields
	user.ID = primitive.NewObjectID()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	// Hash the password
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"endpoint": "/register",
			"method":   "POST",
			"email":    user.Email,
			"error":    err.Error(),
		}).Error("Error hashing password")
		respondWithError(w, http.StatusInternalServerError, "Error hashing password")
		return
	}
	user.Password = hashedPassword

	// Insert the user into the database
	_, err = database.Coll.InsertOne(database.Ctx, user)
	if err != nil {
		logger.Log.WithFields(logrus.Fields{
			"endpoint": "/register",
			"method":   "POST",
			"email":    user.Email,
			"error":    err.Error(),
		}).Error("Error registering user")
		respondWithError(w, http.StatusInternalServerError, "Error registering user")
		return
	}

	logger.Log.WithFields(logrus.Fields{
		"endpoint": "/register",
		"method":   "POST",
		"email":    user.Email,
		"userId":   user.ID.Hex(),
	}).Info("User registered successfully")

	// Return the user data without password
	user.Password = ""
	respondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "User registered successfully",
		"user": map[string]interface{}{
			"id":        user.ID.Hex(),
			"email":     user.Email,
			"createdAt": user.CreatedAt,
		},
	})
}
