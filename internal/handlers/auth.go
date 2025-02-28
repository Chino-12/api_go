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
)

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

	// Generate a JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": dbUser.Email,
		"exp":   time.Now().Add(TOKEN_EXPIRATION).Unix(),
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
	}).Info("Login successful")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":   tokenString,
		"message": "Login successful",
	})
}

func respondWithError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"message": message,
	})
}

func Register(w http.ResponseWriter, r *http.Request) {
	var user models.User

	// Decode the body of the resquest
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Datos inválidos", http.StatusBadRequest)
		return
	}

	// Hashear the password
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		http.Error(w, "Error al hashear la contraseña", http.StatusInternalServerError)
		return
	}
	user.Password = hashedPassword

	// insert the user into the database
	_, err = database.Coll.InsertOne(database.Ctx, user)
	if err != nil {
		http.Error(w, "Error al registrar el usuario", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Usuario registrado"})

}
