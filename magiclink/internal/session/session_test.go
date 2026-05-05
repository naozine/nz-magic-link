package session

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/naozine/nz-magic-link/magiclink/internal/storage"
)

// setupManager creates a session Manager backed by a temporary SQLite database.
func setupManager(t *testing.T) (*Manager, *storage.SQLiteDB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := storage.NewSQLiteDB(storage.Config{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := Config{
		CookieName:     "session",
		CookieSecure:   false,
		CookieHTTPOnly: true,
		CookieSameSite: "lax",
		CookiePath:     "/",
		SessionExpiry:  1 * time.Hour,
	}
	return New(db, cfg), db
}

// findCookie returns the first cookie with the given name, or nil.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestCreate(t *testing.T) {
	mgr, db := setupManager(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if err := mgr.Create(rec, req, "user@example.com"); err != nil {
		t.Fatal(err)
	}

	cookie := findCookie(rec.Result().Cookies(), "session")
	if cookie == nil {
		t.Fatal("expected session cookie to be set")
	}
	if cookie.Value == "" {
		t.Error("expected non-empty session cookie value")
	}

	// Verify session was saved in DB
	sessionID, userID, _, err := db.GetSessionByHash(hashSession(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if sessionID == "" {
		t.Error("expected session to be saved in DB")
	}
	if userID != "user@example.com" {
		t.Errorf("expected userID user@example.com, got %q", userID)
	}
}

func TestCreate_CookieAttributes(t *testing.T) {
	mgr, _ := setupManager(t)
	mgr.Config.CookieSecure = true
	mgr.Config.CookieHTTPOnly = true
	mgr.Config.CookieSameSite = "strict"
	mgr.Config.CookiePath = "/app"
	mgr.Config.CookieDomain = "example.com"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if err := mgr.Create(rec, req, "user@example.com"); err != nil {
		t.Fatal(err)
	}

	cookie := findCookie(rec.Result().Cookies(), "session")
	if cookie == nil {
		t.Fatal("expected session cookie")
	}
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly true")
	}
	if !cookie.Secure {
		t.Error("expected Secure true")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSite=Strict, got %v", cookie.SameSite)
	}
	if cookie.Path != "/app" {
		t.Errorf("expected Path=/app, got %q", cookie.Path)
	}
	if cookie.Domain != "example.com" {
		t.Errorf("expected Domain=example.com, got %q", cookie.Domain)
	}
	// Expires should be roughly now+1h
	expectedExpiry := time.Now().Add(1 * time.Hour)
	if cookie.Expires.Sub(expectedExpiry).Abs() > 10*time.Second {
		t.Errorf("expected Expires near %v, got %v", expectedExpiry, cookie.Expires)
	}
}

func TestCreateWithTokenUsed(t *testing.T) {
	mgr, db := setupManager(t)

	// Save a token first
	tokenHash := "tok-hash-1"
	if err := db.SaveToken("rawtok", tokenHash, "user@example.com", time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.CreateWithTokenUsed(rec, req, "user@example.com", tokenHash); err != nil {
		t.Fatal(err)
	}

	// Token should be marked used
	_, _, _, used, err := db.GetTokenByHash(tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("expected token to be marked as used")
	}

	// Session should be created
	cookie := findCookie(rec.Result().Cookies(), "session")
	if cookie == nil {
		t.Fatal("expected session cookie")
	}
	sessionID, userID, _, err := db.GetSessionByHash(hashSession(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if sessionID == "" {
		t.Error("expected session row to exist")
	}
	if userID != "user@example.com" {
		t.Errorf("expected userID user@example.com, got %q", userID)
	}
}

func TestValidate_Success(t *testing.T) {
	mgr, _ := setupManager(t)

	// Create a session first
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.Create(createRec, createReq, "user@example.com"); err != nil {
		t.Fatal(err)
	}
	sessionCookie := findCookie(createRec.Result().Cookies(), "session")

	// Validate with that cookie
	validateRec := httptest.NewRecorder()
	validateReq := httptest.NewRequest(http.MethodGet, "/", nil)
	validateReq.AddCookie(sessionCookie)

	userID, ok, err := mgr.Validate(validateRec, validateReq)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if userID != "user@example.com" {
		t.Errorf("expected userID user@example.com, got %q", userID)
	}

	// Rolling expiration: a refreshed cookie should be set on response
	refreshed := findCookie(validateRec.Result().Cookies(), "session")
	if refreshed == nil {
		t.Error("expected refreshed cookie on response (rolling expiration)")
	}
	if refreshed != nil && refreshed.Value != sessionCookie.Value {
		t.Error("rolling expiration should keep the same session ID")
	}
}

func TestValidate_NoCookie(t *testing.T) {
	mgr, _ := setupManager(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	userID, ok, err := mgr.Validate(rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false for missing cookie")
	}
	if userID != "" {
		t.Errorf("expected empty userID, got %q", userID)
	}
}

func TestValidate_NonexistentSession(t *testing.T) {
	mgr, _ := setupManager(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "bogus-value"})

	userID, ok, err := mgr.Validate(rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false for unknown session")
	}
	if userID != "" {
		t.Errorf("expected empty userID, got %q", userID)
	}
}

func TestValidate_ExpiredSession(t *testing.T) {
	mgr, db := setupManager(t)

	// Insert an expired session directly
	sessionID := "expired-session-id"
	sessionHash := hashSession(sessionID)
	if err := db.SaveSession(sessionID, sessionHash, "user@example.com", time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})

	userID, ok, err := mgr.Validate(rec, req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false for expired session")
	}
	if userID != "" {
		t.Errorf("expected empty userID, got %q", userID)
	}

	// Expired session should be deleted from DB
	gotID, _, _, err := db.GetSessionByHash(sessionHash)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != "" {
		t.Error("expected expired session to be deleted from DB")
	}
}

func TestValidate_RollingExpiration(t *testing.T) {
	mgr, db := setupManager(t)
	mgr.Config.SessionExpiry = 1 * time.Hour

	// Create a session
	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.Create(createRec, createReq, "user@example.com"); err != nil {
		t.Fatal(err)
	}
	sessionCookie := findCookie(createRec.Result().Cookies(), "session")
	originalCookieExpiry := sessionCookie.Expires

	// Read original DB expiry
	_, _, originalDBExpiry, err := db.GetSessionByHash(hashSession(sessionCookie.Value))
	if err != nil {
		t.Fatal(err)
	}

	// Wait briefly so the new expiry will be measurably later
	time.Sleep(1100 * time.Millisecond)

	// Validate — should refresh the expiry
	validateRec := httptest.NewRecorder()
	validateReq := httptest.NewRequest(http.MethodGet, "/", nil)
	validateReq.AddCookie(sessionCookie)
	if _, ok, err := mgr.Validate(validateRec, validateReq); err != nil || !ok {
		t.Fatalf("expected validate ok, got ok=%v err=%v", ok, err)
	}

	// New cookie should have a later expiry
	refreshed := findCookie(validateRec.Result().Cookies(), "session")
	if refreshed == nil {
		t.Fatal("expected refreshed cookie")
	}
	if !refreshed.Expires.After(originalCookieExpiry) {
		t.Errorf("expected refreshed cookie expiry %v to be after original %v", refreshed.Expires, originalCookieExpiry)
	}

	// DB expiry should also be extended
	_, _, newDBExpiry, err := db.GetSessionByHash(hashSession(sessionCookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if !newDBExpiry.After(originalDBExpiry) {
		t.Errorf("expected refreshed DB expiry %v to be after original %v", newDBExpiry, originalDBExpiry)
	}
}

func TestValidateReadOnly_Success(t *testing.T) {
	mgr, _ := setupManager(t)

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.Create(createRec, createReq, "user@example.com"); err != nil {
		t.Fatal(err)
	}
	sessionCookie := findCookie(createRec.Result().Cookies(), "session")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie)

	userID, ok, err := mgr.ValidateReadOnly(req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if userID != "user@example.com" {
		t.Errorf("expected userID user@example.com, got %q", userID)
	}
}

func TestValidateReadOnly_NoCookie(t *testing.T) {
	mgr, _ := setupManager(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	userID, ok, err := mgr.ValidateReadOnly(req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false for missing cookie")
	}
	if userID != "" {
		t.Errorf("expected empty userID, got %q", userID)
	}
}

func TestValidateReadOnly_ExpiredSession(t *testing.T) {
	mgr, db := setupManager(t)

	sessionID := "expired-session-id"
	sessionHash := hashSession(sessionID)
	if err := db.SaveSession(sessionID, sessionHash, "user@example.com", time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: sessionID})

	userID, ok, err := mgr.ValidateReadOnly(req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false for expired session")
	}
	if userID != "" {
		t.Errorf("expected empty userID, got %q", userID)
	}

	gotID, _, _, err := db.GetSessionByHash(sessionHash)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != "" {
		t.Error("expected expired session to be deleted from DB")
	}
}

func TestInvalidate(t *testing.T) {
	mgr, db := setupManager(t)

	createRec := httptest.NewRecorder()
	createReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := mgr.Create(createRec, createReq, "user@example.com"); err != nil {
		t.Fatal(err)
	}
	sessionCookie := findCookie(createRec.Result().Cookies(), "session")

	// Invalidate with that cookie
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie)
	if err := mgr.Invalidate(rec, req); err != nil {
		t.Fatal(err)
	}

	// Session should be deleted from DB
	gotID, _, _, err := db.GetSessionByHash(hashSession(sessionCookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if gotID != "" {
		t.Error("expected session to be deleted from DB")
	}

	// An expired clearing cookie should be sent
	expired := findCookie(rec.Result().Cookies(), "session")
	if expired == nil {
		t.Fatal("expected clearing cookie on response")
	}
	if expired.MaxAge != -1 {
		t.Errorf("expected MaxAge=-1, got %d", expired.MaxAge)
	}
	if expired.Value != "" {
		t.Errorf("expected empty cookie value, got %q", expired.Value)
	}
}

func TestInvalidate_NoCookie(t *testing.T) {
	mgr, _ := setupManager(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if err := mgr.Invalidate(rec, req); err != nil {
		t.Fatalf("expected no error for missing cookie, got %v", err)
	}
}

func TestCleanupExpired(t *testing.T) {
	mgr, db := setupManager(t)

	// Insert one expired and one valid session
	if err := db.SaveSession("sid-expired", "shash-expired", "user@example.com", time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveSession("sid-valid", "shash-valid", "user@example.com", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := mgr.CleanupExpired(); err != nil {
		t.Fatal(err)
	}

	// Expired should be gone
	expiredID, _, _, err := db.GetSessionByHash("shash-expired")
	if err != nil {
		t.Fatal(err)
	}
	if expiredID != "" {
		t.Error("expected expired session to be removed")
	}

	// Valid should remain
	validID, _, _, err := db.GetSessionByHash("shash-valid")
	if err != nil {
		t.Fatal(err)
	}
	if validID == "" {
		t.Error("expected valid session to be preserved")
	}
}
