package utils

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashea a passwor using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14) // Costo de hash: 14
	return string(bytes), err
}

// CheckPasswordHash compare a password with its hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
