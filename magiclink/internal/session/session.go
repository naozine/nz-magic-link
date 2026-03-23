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
func (m *Manager) Create(w http.ResponseWriter, r *http.Request, userID string) error {
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

	m.setCookie(w, sessionID, expiresAt)
	return nil
}

// CreateWithTokenUsed atomically marks a token as used and creates a new session in a single transaction.
func (m *Manager) CreateWithTokenUsed(w http.ResponseWriter, r *http.Request, userID string, tokenHash string) error {
	sessionID, err := generateSecureToken(32)
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	sessionHash := hashSession(sessionID)
	expiresAt := time.Now().Add(m.Config.SessionExpiry)

	err = m.DB.MarkTokenUsedAndCreateSession(tokenHash, sessionID, sessionHash, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	m.setCookie(w, sessionID, expiresAt)
	return nil
}

// Validate checks if a session is valid and returns the associated user ID if it is.
func (m *Manager) Validate(w http.ResponseWriter, r *http.Request) (string, bool, error) {
	// Get the session cookie
	cookie, err := r.Cookie(m.Config.CookieName)
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
		m.setCookie(w, cookie.Value, newExpiresAt)
	}

	return userID, true, nil
}

// ValidateReadOnly checks if a session is valid without writing anything to the response.
// It does not perform rolling expiration updates.
func (m *Manager) ValidateReadOnly(r *http.Request) (string, bool, error) {
	cookie, err := r.Cookie(m.Config.CookieName)
	if err != nil {
		return "", false, nil
	}

	sessionHash := hashSession(cookie.Value)

	sessionID, userID, expiresAt, err := m.DB.GetSessionByHash(sessionHash)
	if err != nil {
		return "", false, fmt.Errorf("failed to get session: %w", err)
	}

	if sessionID == "" {
		return "", false, nil
	}

	if time.Now().After(expiresAt) {
		_ = m.DB.DeleteSession(sessionHash)
		return "", false, nil
	}

	return userID, true, nil
}

// Invalidate removes the session from the database and clears the session cookie.
func (m *Manager) Invalidate(w http.ResponseWriter, r *http.Request) error {
	// Get the session cookie
	cookie, err := r.Cookie(m.Config.CookieName)
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

	http.SetCookie(w, expiredCookie)
	return nil
}

// CleanupExpired removes expired sessions from the database.
func (m *Manager) CleanupExpired() error {
	return m.DB.CleanupExpiredSessions()
}

// setCookie sets a session cookie on the response.
func (m *Manager) setCookie(w http.ResponseWriter, sessionID string, expiresAt time.Time) {
	cookie := &http.Cookie{
		Name:     m.Config.CookieName,
		Value:    sessionID,
		Path:     m.Config.CookiePath,
		Domain:   m.Config.CookieDomain,
		Expires:  expiresAt,
		Secure:   m.Config.CookieSecure,
		HttpOnly: m.Config.CookieHTTPOnly,
	}

	switch m.Config.CookieSameSite {
	case "strict":
		cookie.SameSite = http.SameSiteStrictMode
	case "lax":
		cookie.SameSite = http.SameSiteLaxMode
	case "none":
		cookie.SameSite = http.SameSiteNoneMode
	}

	http.SetCookie(w, cookie)
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
