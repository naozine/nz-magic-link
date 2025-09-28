// Package session provides functionality for managing user sessions.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/naozine/nz-magic-link/magiclink/internal/storage"
)

// Config holds the configuration for session management.
type Config struct {
	CookieName     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite string
	CookieDomain   string
	CookiePath     string
	SessionExpiry  time.Duration
}

// Manager handles session creation and validation.
type Manager struct {
	DB     storage.Database
	Config Config
}

// New creates a new session manager.
func New(db storage.Database, config Config) *Manager {
	return &Manager{
		DB:     db,
		Config: config,
	}
}

// Create creates a new session for the given user ID and sets a cookie in the response.
func (m *Manager) Create(c echo.Context, userID string) error {
	// Generate a secure session ID
	sessionID, err := generateSecureToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Hash the session ID for storage
	sessionHash := hashSession(sessionID)

	// Calculate expiry time
	expiresAt := time.Now().Add(m.Config.SessionExpiry)

	// Save the session to the database
	err = m.DB.SaveSession(sessionID, sessionHash, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	// Set the session cookie
	cookie := &http.Cookie{
		Name:     m.Config.CookieName,
		Value:    sessionID,
		Path:     m.Config.CookiePath,
		Domain:   m.Config.CookieDomain,
		Expires:  expiresAt,
		Secure:   m.Config.CookieSecure,
		HttpOnly: m.Config.CookieHTTPOnly,
	}

	// Set SameSite attribute
	switch m.Config.CookieSameSite {
	case "strict":
		cookie.SameSite = http.SameSiteStrictMode
	case "lax":
		cookie.SameSite = http.SameSiteLaxMode
	case "none":
		cookie.SameSite = http.SameSiteNoneMode
	}

	c.SetCookie(cookie)
	return nil
}

// Validate checks if a session is valid and returns the associated user ID if it is.
func (m *Manager) Validate(c echo.Context) (string, bool, error) {
	// Get the session cookie
	cookie, err := c.Cookie(m.Config.CookieName)
	if err != nil {
		return "", false, nil // No error, just no valid session
	}

	// Hash the session ID for lookup
	sessionHash := hashSession(cookie.Value)

	// Get the session from the database
	sessionID, userID, expiresAt, err := m.DB.GetSessionByHash(sessionHash)
	if err != nil {
		return "", false, fmt.Errorf("failed to get session: %w", err)
	}

	// Check if the session exists
	if sessionID == "" {
		return "", false, nil
	}

	// Check if the session has expired
	now := time.Now()
	if now.After(expiresAt) {
		// Delete the expired session
		_ = m.DB.DeleteSession(sessionHash)
		return "", false, nil
	}

	// Rolling expiration: extend expiry and update cookie (best-effort)
	newExpiresAt := now.Add(m.Config.SessionExpiry)
	if err := m.DB.UpdateSessionExpiry(sessionHash, newExpiresAt); err == nil {
		updatedCookie := &http.Cookie{
			Name:     m.Config.CookieName,
			Value:    cookie.Value,
			Path:     m.Config.CookiePath,
			Domain:   m.Config.CookieDomain,
			Expires:  newExpiresAt,
			Secure:   m.Config.CookieSecure,
			HttpOnly: m.Config.CookieHTTPOnly,
		}
		// Set SameSite attribute same as on Create
		switch m.Config.CookieSameSite {
		case "strict":
			updatedCookie.SameSite = http.SameSiteStrictMode
		case "lax":
			updatedCookie.SameSite = http.SameSiteLaxMode
		case "none":
			updatedCookie.SameSite = http.SameSiteNoneMode
		}
		c.SetCookie(updatedCookie)
	}

	return userID, true, nil
}

// Invalidate removes the session from the database and clears the session cookie.
func (m *Manager) Invalidate(c echo.Context) error {
	// Get the session cookie
	cookie, err := c.Cookie(m.Config.CookieName)
	if err != nil {
		return nil // No error, just no valid session to invalidate
	}

	// Hash the session ID for lookup
	sessionHash := hashSession(cookie.Value)

	// Delete the session from the database
	err = m.DB.DeleteSession(sessionHash)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	// Clear the session cookie
	expiredCookie := &http.Cookie{
		Name:     m.Config.CookieName,
		Value:    "",
		Path:     m.Config.CookiePath,
		Domain:   m.Config.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   m.Config.CookieSecure,
		HttpOnly: m.Config.CookieHTTPOnly,
	}

	c.SetCookie(expiredCookie)
	return nil
}

// CleanupExpired removes expired sessions from the database.
func (m *Manager) CleanupExpired() error {
	return m.DB.CleanupExpiredSessions()
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

// hashSession creates a SHA-256 hash of the session ID.
func hashSession(sessionID string) string {
	hash := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(hash[:])
}
