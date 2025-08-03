// Package token provides functionality for generating and validating secure tokens.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/naozine/nz-magic-link/magiclink/internal/db"
)

// Manager handles token generation and validation.
type Manager struct {
	DB          *db.DB
	TokenExpiry time.Duration
}

// New creates a new token manager.
func New(db *db.DB, tokenExpiry time.Duration) *Manager {
	return &Manager{
		DB:          db,
		TokenExpiry: tokenExpiry,
	}
}

// Generate creates a new secure token for the given email.
func (m *Manager) Generate(email string) (string, error) {
	// Generate a random token
	token, err := generateSecureToken(32) // 32 bytes = 256 bits
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Hash the token for storage
	tokenHash := hashToken(token)

	// Calculate expiry time
	expiresAt := time.Now().Add(m.TokenExpiry)

	// Save the token to the database
	err = m.DB.SaveToken(token, tokenHash, email, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to save token: %w", err)
	}

	return token, nil
}

// Validate checks if a token is valid and returns the associated email if it is.
func (m *Manager) Validate(token string) (string, error) {
	// Hash the token for lookup
	tokenHash := hashToken(token)

	// Get the token from the database
	storedToken, email, expiresAt, used, err := m.DB.GetTokenByHash(tokenHash)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	// Check if the token exists
	if storedToken == "" {
		return "", fmt.Errorf("invalid token")
	}

	// Check if the token has expired
	if time.Now().After(expiresAt) {
		return "", fmt.Errorf("token has expired")
	}

	// Check if the token has already been used
	if used {
		return "", fmt.Errorf("token has already been used")
	}

	// Mark the token as used
	err = m.DB.MarkTokenAsUsed(tokenHash)
	if err != nil {
		return "", fmt.Errorf("failed to mark token as used: %w", err)
	}

	return email, nil
}

// CheckRateLimit checks if the user has exceeded the rate limit for token generation.
func (m *Manager) CheckRateLimit(email string, maxAttempts int, window time.Duration) (bool, error) {
	// Calculate the time window
	since := time.Now().Add(-window)

	// Count the number of tokens generated for this email in the time window
	count, err := m.DB.CountRecentTokens(email, since)
	if err != nil {
		return false, fmt.Errorf("failed to check rate limit: %w", err)
	}

	// Check if the count exceeds the maximum allowed attempts
	return count >= maxAttempts, nil
}

// CleanupExpired removes expired tokens from the database.
func (m *Manager) CleanupExpired() error {
	return m.DB.CleanupExpiredTokens()
}

// generateSecureToken generates a cryptographically secure random token.
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes), nil
}

// hashToken creates a SHA-256 hash of the token.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
