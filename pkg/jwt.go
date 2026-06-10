package pkg

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type CustomClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// GenerateSession generates a new JWT token signed with JWT_SECRET containing the user's email.
func GenerateSession(email string) (string, error) {
	claims := &CustomClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(os.Getenv("JWT_SECRET")))
}

// VerifySession parses, validates, and returns the email from the session JWT token.
func VerifySession(tokenString string) (string, error) {
	var claims CustomClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired session")
	}
	return claims.Email, nil
}
