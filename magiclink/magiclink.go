// Package magiclink provides a passwordless authentication system using magic links
// sent via email for Go applications using the Echo web framework.
package magiclink

import (
	"fmt"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/naozine/nz-magic-link/magiclink/handlers"
	"github.com/naozine/nz-magic-link/magiclink/internal/db"
	"github.com/naozine/nz-magic-link/magiclink/internal/email"
	"github.com/naozine/nz-magic-link/magiclink/internal/session"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

// Config holds the configuration for the magic link authentication system.
type Config struct {
	// Database configuration
	DatabasePath string

	// Email configuration
	SMTPHost        string
	SMTPPort        int
	SMTPUsername    string
	SMTPPassword    string
	SMTPFrom        string
	SMTPFromName    string
	SMTPUseTLS      bool // Use TLS from the start (port 465)
	SMTPUseSTARTTLS bool // Use STARTTLS (port 587)
	SMTPSkipVerify  bool // Skip TLS certificate verification

	// Token configuration
	TokenExpiry time.Duration

	// Session configuration
	SessionExpiry  time.Duration
	CookieName     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite string
	CookieDomain   string
	CookiePath     string

	// URL configuration
	LoginURL          string
	VerifyURL         string
	RedirectURL       string
	LogoutRedirectURL string
	EmailTemplate     string
	ServerAddr        string

	// Rate limiting
	MaxLoginAttempts int
	RateLimitWindow  time.Duration
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() Config {
	return Config{
		DatabasePath:      "magiclink.db",
		SMTPPort:          587,
		SMTPUseSTARTTLS:   true, // Default to STARTTLS for port 587
		SMTPUseTLS:        false,
		SMTPSkipVerify:    false,
		TokenExpiry:       30 * time.Minute,
		SessionExpiry:     7 * 24 * time.Hour, // 7 days
		CookieName:        "session",
		CookieSecure:      true,
		CookieHTTPOnly:    true,
		CookieSameSite:    "lax",
		CookiePath:        "/",
		LoginURL:          "/auth/login",
		VerifyURL:         "/auth/verify",
		RedirectURL:       "/",
		LogoutRedirectURL: "/",
		ServerAddr:        "http://localhost:8080",
		MaxLoginAttempts:  5,
		RateLimitWindow:   15 * time.Minute,
	}
}

// MagicLink is the main struct that holds the configuration and provides
// methods for the magic link authentication system.
type MagicLink struct {
	Config         Config
	Echo           *echo.Echo
	DB             *db.DB
	TokenManager   *token.Manager
	EmailSender    *email.Sender
	SessionManager *session.Manager
}

// New creates a new MagicLink instance with the provided configuration.
func New(config Config) (*MagicLink, error) {
	// Initialize the database
	database, err := db.New(config.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize the database schema
	if err := database.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	// Initialize the token manager
	tokenManager := token.New(database, config.TokenExpiry)

	// Initialize the email sender
	emailConfig := email.Config{
		Host:          config.SMTPHost,
		Port:          config.SMTPPort,
		Username:      config.SMTPUsername,
		Password:      config.SMTPPassword,
		From:          config.SMTPFrom,
		FromName:      config.SMTPFromName,
		Template:      config.EmailTemplate,
		VerifyURL:     config.VerifyURL,
		ServerAddr:    config.ServerAddr,
		UseTLS:        config.SMTPUseTLS,
		UseSTARTTLS:   config.SMTPUseSTARTTLS,
		SkipTLSVerify: config.SMTPSkipVerify,
	}
	emailSender := email.New(emailConfig)

	// Initialize the session manager
	sessionConfig := session.Config{
		CookieName:     config.CookieName,
		CookieSecure:   config.CookieSecure,
		CookieHTTPOnly: config.CookieHTTPOnly,
		CookieSameSite: config.CookieSameSite,
		CookieDomain:   config.CookieDomain,
		CookiePath:     config.CookiePath,
		SessionExpiry:  config.SessionExpiry,
	}
	sessionManager := session.New(database, sessionConfig)

	return &MagicLink{
		Config:         config,
		DB:             database,
		TokenManager:   tokenManager,
		EmailSender:    emailSender,
		SessionManager: sessionManager,
	}, nil
}

// RegisterHandlers registers the necessary handlers with the Echo instance.
func (m *MagicLink) RegisterHandlers(e *echo.Echo) {
	m.Echo = e

	// Register the handlers
	e.POST(m.Config.LoginURL, handlers.LoginHandler(
		m.TokenManager,
		m.EmailSender,
		m.Config.MaxLoginAttempts,
		m.Config.RateLimitWindow,
	))

	e.GET(m.Config.VerifyURL, handlers.VerifyHandler(
		m.TokenManager,
		m.SessionManager,
		m.Config.RedirectURL,
	))

	// Register the logout handler
	e.POST("/auth/logout", handlers.LogoutHandler(
		m.SessionManager,
		m.Config.LogoutRedirectURL,
	))
}

// AuthMiddleware returns a middleware that checks if the user is authenticated.
func (m *MagicLink) AuthMiddleware() echo.MiddlewareFunc {
	return handlers.AuthMiddleware(m.SessionManager)
}

// Logout invalidates the user's session.
func (m *MagicLink) Logout(c echo.Context) error {
	return m.SessionManager.Invalidate(c)
}

// GetUserID returns the user ID from the session.
func (m *MagicLink) GetUserID(c echo.Context) (string, bool) {
	userID, authenticated, _ := m.SessionManager.Validate(c)
	return userID, authenticated
}

// CleanupExpiredTokens removes expired tokens from the database.
func (m *MagicLink) CleanupExpiredTokens() error {
	return m.TokenManager.CleanupExpired()
}

// CleanupExpiredSessions removes expired sessions from the database.
func (m *MagicLink) CleanupExpiredSessions() error {
	return m.SessionManager.CleanupExpired()
}
