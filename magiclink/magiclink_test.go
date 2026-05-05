package magiclink

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/naozine/nz-magic-link/magiclink/internal/storage"
)

// setupConfig returns a default Config wired to a temp SQLite DB.
// Pass a modifier to override fields. SMTP/DevBypass are unset by default.
func setupConfig(t *testing.T, modify func(*Config)) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.DatabasePath = filepath.Join(t.TempDir(), "test.db")
	if modify != nil {
		modify(&cfg)
	}
	return cfg
}

// setupMagicLink creates a MagicLink instance using setupConfig and registers cleanup.
func setupMagicLink(t *testing.T, modify func(*Config)) *MagicLink {
	t.Helper()
	ml, err := New(setupConfig(t, modify))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ml.Close() })
	return ml
}

// --- DefaultConfig ---

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()

	checks := map[string]bool{
		"DatabaseType=sqlite":                cfg.DatabaseType == "sqlite",
		"SMTPPort=587":                       cfg.SMTPPort == 587,
		"SMTPUseSTARTTLS=true":               cfg.SMTPUseSTARTTLS,
		"UseInMemoryTokens=true":             cfg.UseInMemoryTokens,
		"TokenExpiry=30m":                    cfg.TokenExpiry == 30*time.Minute,
		"SessionExpiry=7d":                   cfg.SessionExpiry == 7*24*time.Hour,
		"CookieSecure=true":                  cfg.CookieSecure,
		"CookieHTTPOnly=true":                cfg.CookieHTTPOnly,
		"MaxLoginAttempts=5":                 cfg.MaxLoginAttempts == 5,
		"WebAuthnEnabled=false":              !cfg.WebAuthnEnabled,
		"WebAuthnRequireResidentKey=true":    cfg.WebAuthnRequireResidentKey,
		"WebAuthnUserVerification=preferred": cfg.WebAuthnUserVerification == "preferred",
	}
	for name, ok := range checks {
		if !ok {
			t.Errorf("default check failed: %s", name)
		}
	}
}

// --- New ---

func TestNew_HappyPath(t *testing.T) {
	ml := setupMagicLink(t, nil)

	if ml.DB == nil {
		t.Error("expected DB to be set")
	}
	if ml.TokenManager == nil {
		t.Error("expected TokenManager to be set")
	}
	if ml.EmailSender == nil {
		t.Error("expected EmailSender to be set")
	}
	if ml.SessionManager == nil {
		t.Error("expected SessionManager to be set")
	}
	if ml.EmailChecker == nil {
		t.Error("expected EmailChecker to be set")
	}
	// WebAuthn disabled by default
	if ml.WebAuthnService != nil {
		t.Error("expected WebAuthnService to be nil when disabled")
	}
}

func TestNew_FailsWithInvalidDBPath(t *testing.T) {
	cfg := DefaultConfig()
	// Path inside a non-existent, non-creatable directory
	cfg.DatabasePath = "/nonexistent/dir/that/cannot/be/created/test.db"

	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for invalid DB path")
	}
}

func TestNew_UseInMemoryTokens_WrapsDB(t *testing.T) {
	mlOn := setupMagicLink(t, func(c *Config) { c.UseInMemoryTokens = true })
	if _, ok := mlOn.DB.(*storage.MemoryTokenStore); !ok {
		t.Errorf("expected DB to be wrapped in MemoryTokenStore when UseInMemoryTokens=true, got %T", mlOn.DB)
	}

	mlOff := setupMagicLink(t, func(c *Config) { c.UseInMemoryTokens = false })
	if _, ok := mlOff.DB.(*storage.MemoryTokenStore); ok {
		t.Errorf("expected DB to NOT be wrapped when UseInMemoryTokens=false, got %T", mlOff.DB)
	}
}

// --- NewWithDB ---

func TestNewWithDB_UsesInjectedDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "injected.db")
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawDB.Close() })

	cfg := DefaultConfig()
	cfg.DatabaseType = "sqlite"
	cfg.DatabasePath = dbPath
	ml, err := NewWithDB(cfg, rawDB)
	if err != nil {
		t.Fatal(err)
	}
	if ml.DB == nil {
		t.Error("expected DB to be set from injected connection")
	}
}

// --- WebAuthn ---

func TestNew_WebAuthnDisabled_NoService(t *testing.T) {
	ml := setupMagicLink(t, func(c *Config) { c.WebAuthnEnabled = false })
	if ml.WebAuthnService != nil {
		t.Error("expected WebAuthnService to be nil when disabled")
	}
}

func TestNew_WebAuthnEnabled_HasService(t *testing.T) {
	ml := setupMagicLink(t, func(c *Config) {
		c.WebAuthnEnabled = true
		c.WebAuthnRPID = "localhost"
		c.WebAuthnAllowedOrigins = []string{"http://localhost:8080"}
	})
	if ml.WebAuthnService == nil {
		t.Error("expected WebAuthnService to be initialized when enabled")
	}
}

// --- Dev bypass emails ---

func TestNew_LoadsDevBypassEmailsAndPatterns(t *testing.T) {
	bypassPath := filepath.Join(t.TempDir(), "bypass.txt")
	content := `# this is a comment
admin@example.com

# blank line above
*@test.com
user@example.com
?-pattern@example.com
`
	if err := os.WriteFile(bypassPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	ml := setupMagicLink(t, func(c *Config) { c.DevBypassEmailFilePath = bypassPath })

	if !ml.DevBypassEmails["admin@example.com"] {
		t.Error("expected admin@example.com in DevBypassEmails")
	}
	if !ml.DevBypassEmails["user@example.com"] {
		t.Error("expected user@example.com in DevBypassEmails")
	}
	if ml.DevBypassEmails["# this is a comment"] {
		t.Error("expected comment lines to be skipped")
	}
	if len(ml.DevBypassPatterns) != 2 {
		t.Errorf("expected 2 patterns, got %d (%v)", len(ml.DevBypassPatterns), ml.DevBypassPatterns)
	}
}

func TestNew_DevBypassFile_NotFound(t *testing.T) {
	cfg := setupConfig(t, func(c *Config) {
		c.DevBypassEmailFilePath = "/nonexistent/bypass.txt"
	})
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for missing bypass file")
	}
}

// --- Email domain whitelist ---

func TestNew_LoadsEmailWhitelist(t *testing.T) {
	whitelistPath := filepath.Join(t.TempDir(), "whitelist.txt")
	if err := os.WriteFile(whitelistPath, []byte("example.com\nallowed.org\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ml := setupMagicLink(t, func(c *Config) { c.EmailDomainWhitelistFile = whitelistPath })
	if ml.EmailChecker == nil {
		t.Fatal("expected EmailChecker to be initialized")
	}
	// We can't easily inspect the internal whitelist; rely on no error path being sufficient.
}

func TestNew_EmailWhitelist_FileNotFound(t *testing.T) {
	cfg := setupConfig(t, func(c *Config) {
		c.EmailDomainWhitelistFile = "/nonexistent/whitelist.txt"
	})
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for missing whitelist file")
	}
}

// --- Handler routes ---

func TestHandler_HasLoginRoute(t *testing.T) {
	ml := setupMagicLink(t, nil)
	h := ml.Handler()

	req := httptest.NewRequest(http.MethodPost, ml.Config.LoginURL, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Errorf("expected login route to be registered, got 404")
	}
}

func TestHandler_HasVerifyRoute(t *testing.T) {
	ml := setupMagicLink(t, nil)
	h := ml.Handler()

	req := httptest.NewRequest(http.MethodGet, ml.Config.VerifyURL, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Errorf("expected verify route to be registered, got 404")
	}
}

func TestHandler_WebAuthnDisabled_NoRoutes(t *testing.T) {
	ml := setupMagicLink(t, func(c *Config) { c.WebAuthnEnabled = false })
	h := ml.Handler()

	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/start", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when WebAuthn disabled, got %d", rec.Code)
	}
}

func TestHandler_WebAuthnEnabled_HasRoutes(t *testing.T) {
	ml := setupMagicLink(t, func(c *Config) {
		c.WebAuthnEnabled = true
		c.WebAuthnRPID = "localhost"
		c.WebAuthnAllowedOrigins = []string{"http://localhost:8080"}
	})
	h := ml.Handler()

	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/start", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusNotFound {
		t.Errorf("expected WebAuthn route to be registered, got 404")
	}
}

// --- ValidateSession ---

func TestValidateSession_NoCookie(t *testing.T) {
	ml := setupMagicLink(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	userID, ok := ml.ValidateSession(req)
	if ok {
		t.Error("expected ok=false for missing cookie")
	}
	if userID != "" {
		t.Errorf("expected empty userID, got %q", userID)
	}
}

func TestValidateSession_Valid(t *testing.T) {
	ml := setupMagicLink(t, nil)

	// Create a session by calling SessionManager directly
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := ml.SessionManager.Create(createRec, createReq, "user@example.com"); err != nil {
		t.Fatal(err)
	}

	// Use the cookie in a new request
	cookies := createRec.Result().Cookies()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	userID, ok := ml.ValidateSession(req)
	if !ok {
		t.Fatal("expected ok=true for valid cookie")
	}
	if userID != "user@example.com" {
		t.Errorf("expected user@example.com, got %q", userID)
	}
}
