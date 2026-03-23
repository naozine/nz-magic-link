// Package magiclink provides a passwordless authentication system using magic links
// sent via email for Go web applications.
package magiclink

import (
	"bufio"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/naozine/nz-magic-link/magiclink/handlers"
	"github.com/naozine/nz-magic-link/magiclink/internal/email"
	"github.com/naozine/nz-magic-link/magiclink/internal/emailcheck"
	"github.com/naozine/nz-magic-link/magiclink/internal/session"
	"github.com/naozine/nz-magic-link/magiclink/internal/storage"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
	"github.com/naozine/nz-magic-link/magiclink/internal/webauthn"
)

// BaseTemplateData is exported from the email package for external use.
// This struct should be embedded in custom data structures to ensure
// compatibility with existing template macros.
type BaseTemplateData = email.BaseTemplateData

// UserIDKey is the context key for the authenticated user ID.
// Use this with r.Context().Value(magiclink.UserIDKey) to retrieve the user ID
// set by AuthMiddleware.
const UserIDKey = handlers.UserIDKey

// Config holds the configuration for the magic link authentication system.
type Config struct {
	// Database configuration
	DatabasePath    string
	DatabaseType    string            // "sqlite" or "leveldb"
	DatabaseOptions map[string]string // Database-specific options

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

	// Development configuration
	// DevBypassEmailFilePath is the path to a file containing email addresses that should bypass email sending.
	// This is useful for development and testing purposes.
	// The file should contain one email address per line.
	// If an email address in this file requests a magic link, the link will be returned in the response
	// instead of being sent via email, allowing for easier testing of the authentication flow.
	DevBypassEmailFilePath string

	// Email domain quality check
	EmailDomainWhitelistFile string                         // Path to whitelist file (1 domain per line)
	EmailDomainBlacklistFile string                         // Path to blacklist file (1 domain per line)
	ValidateEmailMX          bool                           // Enable MX record validation for unknown domains
	OnEmailBlocked           func(email string, reason string) // Callback when email is blocked

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
	ErrorRedirectURL  string
	EmailTemplate     string
	EmailSubject      string
	ServerAddr        string
	// LoginSuccessMessage is the message returned to the user after a successful login request (email sent).
	LoginSuccessMessage string

	// AllowLogin is a callback function that checks if a user is allowed to log in.
	// It takes the request and the email address as arguments.
	// If it returns an error, the login process is aborted and the error message is returned to the user.
	AllowLogin func(r *http.Request, email string) error

	// Token storage
	// UseInMemoryTokens enables in-memory token storage for high-concurrency scenarios.
	// Tokens are stored in memory instead of the database. Sessions still use the database.
	// If the process restarts, pending tokens are lost (users simply re-request login).
	UseInMemoryTokens bool

	// Rate limiting
	MaxLoginAttempts    int
	RateLimitWindow     time.Duration
	DisableRateLimiting bool // Disable all rate limiting (for testing/benchmarking)

	// WebAuthn/Passkey configuration
	WebAuthnRPID               string        `json:"webauthn_rp_id"`
	WebAuthnRPName             string        `json:"webauthn_rp_name"`
	WebAuthnAllowedOrigins     []string      `json:"webauthn_allowed_origins"`
	WebAuthnChallengeTTL       time.Duration `json:"webauthn_challenge_ttl"`
	WebAuthnTimeout            time.Duration `json:"webauthn_timeout"`
	WebAuthnMetadataValidation bool          `json:"webauthn_metadata_validation"`
	WebAuthnUserVerification   string        `json:"webauthn_user_verification"`
	WebAuthnRequireResidentKey bool          `json:"webauthn_require_resident_key"`
	WebAuthnEnabled            bool          `json:"webauthn_enabled"`
	WebAuthnRedirectURL        string        `json:"webauthn_redirect_url"` // Redirect URL after successful WebAuthn login
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() Config {
	return Config{
		DatabasePath:           "magiclink.db",
		DatabaseType:           "sqlite",
		DatabaseOptions:        map[string]string{},
		SMTPPort:               587,
		SMTPUseSTARTTLS:        true, // Default to STARTTLS for port 587
		SMTPUseTLS:             false,
		SMTPSkipVerify:         false,
		DevBypassEmailFilePath: "", // Empty by default
		UseInMemoryTokens:     true,
		TokenExpiry:            30 * time.Minute,
		SessionExpiry:          7 * 24 * time.Hour, // 7 days
		CookieName:             "session",
		CookieSecure:           true,
		CookieHTTPOnly:         true,
		CookieSameSite:         "lax",
		CookiePath:             "/",
		LoginURL:               "/auth/login",
		VerifyURL:              "/auth/verify",
		RedirectURL:            "/",
		LogoutRedirectURL:      "/",
		ErrorRedirectURL:       "",
		EmailSubject:           "Your Magic Link for Authentication",
		ServerAddr:             "http://localhost:8080",
		LoginSuccessMessage:    "Magic link sent to your email",
		MaxLoginAttempts:       5,
		RateLimitWindow:        15 * time.Minute,

		// WebAuthn defaults
		WebAuthnRPID:               "localhost",
		WebAuthnRPName:             "nz-magic-link",
		WebAuthnAllowedOrigins:     []string{"http://localhost:8080"},
		WebAuthnChallengeTTL:       5 * time.Minute,
		WebAuthnTimeout:            60 * time.Second,
		WebAuthnMetadataValidation: false,
		WebAuthnUserVerification:   "preferred",
		WebAuthnRequireResidentKey: true,
		WebAuthnEnabled:            false, // Disabled by default
		WebAuthnRedirectURL:        "/dashboard",
	}
}

// MagicLink is the main struct that holds the configuration and provides
// methods for the magic link authentication system.
type MagicLink struct {
	Config          Config
	DB              storage.Database
	TokenManager    *token.Manager
	EmailSender     *email.Sender
	SessionManager  *session.Manager
	WebAuthnService      *webauthn.Service // WebAuthn service for passkey authentication
	DevBypassEmails      map[string]bool   // Map of email addresses that should bypass email sending
	DevBypassPatterns    []string          // Wildcard patterns for bypass (e.g., "*@test.com")
	EmailChecker         *emailcheck.Checker
}

// New creates a new MagicLink instance with the provided configuration.
func New(config Config) (*MagicLink, error) {
	// Create database configuration
	dbConfig := storage.Config{
		Type:    config.DatabaseType,
		Path:    config.DatabasePath,
		Options: config.DatabaseOptions,
	}

	// Initialize the database using factory
	factory := storage.NewFactory()
	database, err := factory.Create(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return newMagicLink(config, database)
}

// NewWithDB creates a new MagicLink instance with the provided configuration and an existing database connection.
// Currently, this is only supported when DatabaseType is "sqlite".
func NewWithDB(config Config, db *sql.DB) (*MagicLink, error) {
	// Create database configuration
	dbConfig := storage.Config{
		Type:    config.DatabaseType,
		Path:    config.DatabasePath, // Path might not be needed if we inject DB, but good to keep consistent
		Options: config.DatabaseOptions,
	}

	// Initialize the database using factory with injected DB
	factory := storage.NewFactory()
	database, err := factory.CreateWithDB(dbConfig, db)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database with existing connection: %w", err)
	}

	return newMagicLink(config, database)
}

// newMagicLink initializes the MagicLink instance with the provided configuration and database.
func newMagicLink(config Config, database storage.Database) (*MagicLink, error) {
	// Initialize the database schema
	if err := database.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	// Wrap with in-memory token store if enabled
	if config.UseInMemoryTokens {
		database = storage.NewMemoryTokenStore(database, 5*time.Minute)
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
		Subject:       config.EmailSubject,
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

	// Initialize WebAuthn service if enabled
	var webauthnService *webauthn.Service
	if config.WebAuthnEnabled {
		webauthnConfig := webauthn.Config{
			RPID:               config.WebAuthnRPID,
			RPName:             config.WebAuthnRPName,
			AllowedOrigins:     config.WebAuthnAllowedOrigins,
			ChallengeTTL:       config.WebAuthnChallengeTTL,
			Timeout:            config.WebAuthnTimeout,
			MetadataValidation: config.WebAuthnMetadataValidation,
			UserVerification:   config.WebAuthnUserVerification,
			RequireResidentKey: config.WebAuthnRequireResidentKey,
		}

		var err error
		webauthnService, err = webauthn.NewService(webauthnConfig, database)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize WebAuthn service: %w", err)
		}
	}

	// Create the MagicLink instance
	ml := &MagicLink{
		Config:          config,
		DB:              database,
		TokenManager:    tokenManager,
		EmailSender:     emailSender,
		SessionManager:  sessionManager,
		WebAuthnService: webauthnService,
		DevBypassEmails: make(map[string]bool),
	}

	// Load the bypass email addresses if a file path is provided
	if config.DevBypassEmailFilePath != "" {
		if err := ml.loadDevBypassEmails(config.DevBypassEmailFilePath); err != nil {
			return nil, fmt.Errorf("failed to load bypass email addresses: %w", err)
		}
	}

	// Initialize email domain checker
	var whitelist, blacklist map[string]bool
	if config.EmailDomainWhitelistFile != "" {
		var err error
		whitelist, err = emailcheck.LoadDomainFile(config.EmailDomainWhitelistFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load email domain whitelist: %w", err)
		}
	}
	if config.EmailDomainBlacklistFile != "" {
		var err error
		blacklist, err = emailcheck.LoadDomainFile(config.EmailDomainBlacklistFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load email domain blacklist: %w", err)
		}
	}
	ml.EmailChecker = emailcheck.New(emailcheck.Config{
		WhitelistDomains: whitelist,
		BlacklistDomains: blacklist,
		ValidateMX:       config.ValidateEmailMX,
		OnBlocked:        config.OnEmailBlocked,
	})

	return ml, nil
}

// Handler returns an http.Handler that serves all magic link authentication routes.
func (m *MagicLink) Handler() http.Handler {
	mux := http.NewServeMux()

	// Register the login handler
	mux.Handle("POST "+m.Config.LoginURL, handlers.LoginHandler(
		m.TokenManager,
		m.EmailSender,
		m.Config.MaxLoginAttempts,
		m.Config.RateLimitWindow,
		m.DevBypassEmails,
		m.DevBypassPatterns,
		m.Config.ServerAddr,
		m.Config.VerifyURL,
		m.Config.LoginSuccessMessage,
		m.Config.AllowLogin,
		m.Config.DisableRateLimiting,
		m.EmailChecker,
	))

	// Register the verify handler
	mux.Handle("GET "+m.Config.VerifyURL, handlers.VerifyHandler(
		m.TokenManager,
		m.SessionManager,
		m.Config.RedirectURL,
		m.Config.ErrorRedirectURL,
	))

	// Register the logout handler
	mux.Handle("POST /auth/logout", handlers.LogoutHandler(
		m.SessionManager,
		m.Config.LogoutRedirectURL,
	))

	// Register WebAuthn handlers if enabled
	if m.Config.WebAuthnEnabled && m.WebAuthnService != nil {
		webauthnHandlers := handlers.NewWebAuthnHandlers(m.WebAuthnService, *m.SessionManager, WebAuthnClientJS, m.Config.WebAuthnRedirectURL)
		mux.Handle("/webauthn/", http.StripPrefix("/webauthn", webauthnHandlers.Handler()))
	}

	return mux
}

// AuthMiddleware returns a middleware that checks if the user is authenticated.
func (m *MagicLink) AuthMiddleware(next http.Handler) http.Handler {
	return handlers.AuthMiddleware(m.SessionManager)(next)
}

// Logout invalidates the user's session.
func (m *MagicLink) Logout(w http.ResponseWriter, r *http.Request) error {
	return m.SessionManager.Invalidate(w, r)
}

// GetUserID returns the user ID from the request context.
// The user ID is set by AuthMiddleware when the user is authenticated.
func (m *MagicLink) GetUserID(r *http.Request) (string, bool) {
	userID, ok := r.Context().Value(handlers.UserIDKey).(string)
	return userID, ok
}

// CleanupExpiredTokens removes expired tokens from the database.
func (m *MagicLink) CleanupExpiredTokens() error {
	return m.TokenManager.CleanupExpired()
}

// CleanupExpiredSessions removes expired sessions from the database.
func (m *MagicLink) CleanupExpiredSessions() error {
	return m.SessionManager.CleanupExpired()
}

// Close closes the database connection and cleans up resources.
func (m *MagicLink) Close() error {
	return m.DB.Close()
}

// loadDevBypassEmails reads the file at the given path and loads the email addresses into the DevBypassEmails map.
// Each line in the file should contain a single email address or a wildcard pattern (e.g., "*@test.com").
func (m *MagicLink) loadDevBypassEmails(filePath string) (err error) {
	// Initialize the map
	m.DevBypassEmails = make(map[string]bool)
	m.DevBypassPatterns = nil

	// If no file path is provided, return early
	if filePath == "" {
		return nil
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open bypass email file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close bypass email file: %w", closeErr)
		}
	}()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Get the line and trim whitespace
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if the line contains a wildcard pattern
		if strings.ContainsAny(line, "*?[") {
			m.DevBypassPatterns = append(m.DevBypassPatterns, line)
		} else {
			m.DevBypassEmails[line] = true
		}
	}

	// Check for errors
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading bypass email file: %w", err)
	}

	return nil
}
