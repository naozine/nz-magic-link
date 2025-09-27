package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/naozine/nz-magic-link/magiclink/internal/session"
	"github.com/naozine/nz-magic-link/magiclink/internal/storage"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

// mockDB is an in-memory implementation of storage.Database for testing.
type mockDB struct {
	tokens   map[string]mockToken // key: tokenHash
	sessions map[string]mockSession

	// error toggles
	errGetToken      error
	errMarkTokenUsed error
	errSaveSession   error
}

type mockToken struct {
	token     string
	email     string
	expiresAt time.Time
	used      bool
}

type mockSession struct {
	sessionID   string
	sessionHash string
	userID      string
	expiresAt   time.Time
}

func newMockDB() *mockDB {
	return &mockDB{
		tokens:   make(map[string]mockToken),
		sessions: make(map[string]mockSession),
	}
}

// helper to compute token hash locally (replicates internal hashing)
func hashTokenLocal(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// storage.Database implementation
func (m *mockDB) Init() error  { return nil }
func (m *mockDB) Close() error { return nil }
func (m *mockDB) SaveToken(token, tokenHash, email string, expiresAt time.Time) error {
	m.tokens[tokenHash] = mockToken{token: token, email: email, expiresAt: expiresAt}
	return nil
}
func (m *mockDB) GetTokenByHash(tokenHash string) (tokenStr, email string, expiresAt time.Time, used bool, err error) {
	if m.errGetToken != nil {
		return "", "", time.Time{}, false, m.errGetToken
	}
	t, ok := m.tokens[tokenHash]
	if !ok {
		return "", "", time.Time{}, false, nil
	}
	return t.token, t.email, t.expiresAt, t.used, nil
}
func (m *mockDB) MarkTokenAsUsed(tokenHash string) error {
	if m.errMarkTokenUsed != nil {
		return m.errMarkTokenUsed
	}
	t := m.tokens[tokenHash]
	t.used = true
	m.tokens[tokenHash] = t
	return nil
}
func (m *mockDB) CountRecentTokens(email string, since time.Time) (int, error) { return 0, nil }
func (m *mockDB) CleanupExpiredTokens() error                                  { return nil }

func (m *mockDB) SaveSession(sessionID, sessionHash, userID string, expiresAt time.Time) error {
	if m.errSaveSession != nil {
		return m.errSaveSession
	}
	m.sessions[sessionHash] = mockSession{sessionID: sessionID, sessionHash: sessionHash, userID: userID, expiresAt: expiresAt}
	return nil
}
func (m *mockDB) GetSessionByHash(sessionHash string) (sessionID, userID string, expiresAt time.Time, err error) {
	s, ok := m.sessions[sessionHash]
	if !ok {
		return "", "", time.Time{}, nil
	}
	return s.sessionID, s.userID, s.expiresAt, nil
}
func (m *mockDB) DeleteSession(sessionHash string) error { delete(m.sessions, sessionHash); return nil }
func (m *mockDB) CleanupExpiredSessions() error          { return nil }

// Passkey-related methods (stubs for testing)
func (m *mockDB) SavePasskeyCredential(cred *storage.PasskeyCredential) error { return nil }
func (m *mockDB) GetPasskeyCredentialByID(credentialID string) (*storage.PasskeyCredential, error) {
	return nil, nil
}
func (m *mockDB) GetPasskeyCredentialsByUserID(userID string) ([]*storage.PasskeyCredential, error) {
	return nil, nil
}
func (m *mockDB) DeletePasskeyCredential(credentialID string) error { return nil }
func (m *mockDB) UpdatePasskeyCredentialSignCount(credentialID string, signCount uint32) error {
	return nil
}
func (m *mockDB) SavePasskeyChallenge(challenge *storage.PasskeyChallenge) error { return nil }
func (m *mockDB) GetPasskeyChallenge(challengeID string) (*storage.PasskeyChallenge, error) {
	return nil, nil
}
func (m *mockDB) DeletePasskeyChallenge(challengeID string) error { return nil }
func (m *mockDB) CleanupExpiredPasskeyChallenges() error          { return nil }

func (m *mockDB) Ping() error { return nil }

// helper to set up Echo, managers and perform request
func setup(t *testing.T) (*echo.Echo, *token.Manager, *session.Manager, *mockDB) {
	t.Helper()
	e := echo.New()
	db := newMockDB()

	tokenMgr := token.New(db, 15*time.Minute)
	sessMgr := session.New(db, session.Config{
		CookieName:     "session",
		CookieSecure:   false,
		CookieHTTPOnly: true,
		CookieSameSite: "lax",
		CookiePath:     "/",
		SessionExpiry:  time.Hour,
	})
	return e, tokenMgr, sessMgr, db
}

func performRequest(e *echo.Echo, h echo.HandlerFunc, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	_ = h(c)
	return rec
}

func TestVerifyHandler_TokenMissing_JSON(t *testing.T) {
	e, tokenMgr, sessMgr, _ := setup(t)

	handler := VerifyHandler(tokenMgr, sessMgr, "", "")
	rec := performRequest(e, handler, "/auth/verify")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Error != "Token is required" {
		t.Fatalf("expected error message 'Token is required', got %q", resp.Error)
	}
}

func TestVerifyHandler_TokenMissing_Redirect(t *testing.T) {
	e, tokenMgr, sessMgr, _ := setup(t)

	handler := VerifyHandler(tokenMgr, sessMgr, "", "https://example.com/error")
	rec := performRequest(e, handler, "/auth/verify")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect URL: %v", err)
	}
	if u.Scheme != "https" || u.Host != "example.com" || u.Path != "/error" {
		t.Fatalf("unexpected redirect base: %s", loc)
	}
	q := u.Query()
	if q.Get("error") != "token_required" {
		t.Fatalf("expected error=token_required, got %q", q.Get("error"))
	}
	if q.Get("error_description") != "Token is required" {
		t.Fatalf("unexpected error_description: %q", q.Get("error_description"))
	}
	if q.Get("code") != "400" {
		t.Fatalf("expected code=400, got %q", q.Get("code"))
	}
}

func TestVerifyHandler_InvalidToken_JSON(t *testing.T) {
	e, tokenMgr, sessMgr, _ := setup(t)

	handler := VerifyHandler(tokenMgr, sessMgr, "", "")
	rec := performRequest(e, handler, "/auth/verify?token=nonexistent")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
	var resp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp.Error != "invalid token" {
		t.Fatalf("expected 'invalid token', got %q", resp.Error)
	}
}

func TestVerifyHandler_TokenUsed_Redirect_WithOverride(t *testing.T) {
	e, tokenMgr, sessMgr, db := setup(t)

	// prepare a token in DB that is already used
	tok := "token-used"
	tokenHash := hashTokenLocal(tok)
	db.tokens[tokenHash] = mockToken{token: tok, email: "user@example.com", expiresAt: time.Now().Add(10 * time.Minute), used: true}

	handler := VerifyHandler(tokenMgr, sessMgr, "", "https://default.example.com/err")
	rec := performRequest(e, handler, "/auth/verify?token="+url.QueryEscape(tok)+"&error_redirect="+url.QueryEscape("https://override.example.com/path"))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect URL: %v", err)
	}
	if u.Host != "override.example.com" || u.Path != "/path" {
		t.Fatalf("expected override redirect host/path, got %s", loc)
	}
	q := u.Query()
	if q.Get("error") != "token_used" {
		t.Fatalf("expected error=token_used, got %q", q.Get("error"))
	}
	if q.Get("code") != "400" {
		t.Fatalf("expected code=400, got %q", q.Get("code"))
	}
}

func TestVerifyHandler_InternalError_SaveSession_Redirect(t *testing.T) {
	e, tokenMgr, sessMgr, db := setup(t)

	// valid token present
	tok := "valid-token"
	tokenHash := hashTokenLocal(tok)
	db.tokens[tokenHash] = mockToken{token: tok, email: "user2@example.com", expiresAt: time.Now().Add(10 * time.Minute), used: false}
	// make session saving fail
	db.errSaveSession = assertErr("save session failure")

	handler := VerifyHandler(tokenMgr, sessMgr, "", "https://example.com/err")
	rec := performRequest(e, handler, "/auth/verify?token="+url.QueryEscape(tok))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	q := u.Query()
	if q.Get("error") != "internal_error" {
		t.Fatalf("expected internal_error, got %q", q.Get("error"))
	}
	if q.Get("code") != "500" {
		t.Fatalf("expected code=500, got %q", q.Get("code"))
	}
}

func TestVerifyHandler_Success_Redirect_AndCookie(t *testing.T) {
	e, tokenMgr, sessMgr, db := setup(t)

	tok := "ok-token"
	tokenHash := hashTokenLocal(tok)
	db.tokens[tokenHash] = mockToken{token: tok, email: "ok@example.com", expiresAt: time.Now().Add(10 * time.Minute), used: false}

	handler := VerifyHandler(tokenMgr, sessMgr, "https://app.example.com/after", "")
	rec := performRequest(e, handler, "/auth/verify?token="+url.QueryEscape(tok))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://app.example.com/after" {
		t.Fatalf("unexpected redirect location: %s", loc)
	}

	// check that a Set-Cookie header is present for the session cookie
	cookies := rec.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "session" && c.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session cookie to be set")
	}
}

// simple error type to tag expected errors
type assertErr string

func (e assertErr) Error() string { return string(e) }
