package token

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/naozine/nz-magic-link/magiclink/internal/storage"
)

// setupManager creates a token Manager backed by a temporary SQLite database.
func setupManager(t *testing.T, expiry time.Duration) (*Manager, *storage.SQLiteDB) {
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
	return New(db, expiry), db
}

func TestGenerate_ReturnsToken(t *testing.T) {
	mgr, db := setupManager(t, 30*time.Minute)

	token, err := mgr.Generate("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	storedToken, email, _, used, err := db.GetTokenByHash(hashToken(token))
	if err != nil {
		t.Fatal(err)
	}
	if storedToken == "" {
		t.Error("expected token to be stored in DB")
	}
	if email != "user@example.com" {
		t.Errorf("expected email user@example.com, got %q", email)
	}
	if used {
		t.Error("expected fresh token to not be marked as used")
	}
}

func TestGenerate_TokensAreUnique(t *testing.T) {
	mgr, _ := setupManager(t, 30*time.Minute)

	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		token, err := mgr.Generate("user@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if seen[token] {
			t.Fatalf("duplicate token generated: %s", token)
		}
		seen[token] = true
	}
}

func TestValidate_Success(t *testing.T) {
	mgr, db := setupManager(t, 30*time.Minute)

	token, err := mgr.Generate("user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	email, err := mgr.Validate(token)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if email != "user@example.com" {
		t.Errorf("expected email user@example.com, got %q", email)
	}

	_, _, _, used, err := db.GetTokenByHash(hashToken(token))
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("expected token to be marked as used after Validate")
	}
}

func TestValidate_NonexistentToken(t *testing.T) {
	mgr, _ := setupManager(t, 30*time.Minute)

	_, err := mgr.Validate("nonexistent-token-value")
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}
	if err.Error() != "invalid token" {
		t.Errorf("expected 'invalid token', got %q", err.Error())
	}
}

func TestValidate_ExpiredToken(t *testing.T) {
	mgr, db := setupManager(t, 30*time.Minute)

	rawToken := "expired-token"
	if err := db.SaveToken(rawToken, hashToken(rawToken), "user@example.com", time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	_, err := mgr.Validate(rawToken)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if err.Error() != "token has expired" {
		t.Errorf("expected 'token has expired', got %q", err.Error())
	}
}

func TestValidate_AlreadyUsedToken(t *testing.T) {
	mgr, _ := setupManager(t, 30*time.Minute)

	token, err := mgr.Generate("user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mgr.Validate(token); err != nil {
		t.Fatal(err)
	}

	_, err = mgr.Validate(token)
	if err == nil {
		t.Fatal("expected error for already-used token")
	}
	if err.Error() != "token has already been used" {
		t.Errorf("expected 'token has already been used', got %q", err.Error())
	}
}

func TestValidateOnly_Success(t *testing.T) {
	mgr, db := setupManager(t, 30*time.Minute)

	token, err := mgr.Generate("user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	email, tokenHashOut, err := mgr.ValidateOnly(token)
	if err != nil {
		t.Fatalf("ValidateOnly failed: %v", err)
	}
	if email != "user@example.com" {
		t.Errorf("expected email user@example.com, got %q", email)
	}
	if tokenHashOut != hashToken(token) {
		t.Errorf("expected tokenHash %s, got %s", hashToken(token), tokenHashOut)
	}

	// ValidateOnly must NOT mark the token as used
	_, _, _, used, err := db.GetTokenByHash(hashToken(token))
	if err != nil {
		t.Fatal(err)
	}
	if used {
		t.Error("expected token to remain unused after ValidateOnly")
	}
}

func TestValidateOnly_ExpiredToken(t *testing.T) {
	mgr, db := setupManager(t, 30*time.Minute)

	rawToken := "expired-token"
	if err := db.SaveToken(rawToken, hashToken(rawToken), "user@example.com", time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	_, _, err := mgr.ValidateOnly(rawToken)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if err.Error() != "token has expired" {
		t.Errorf("expected 'token has expired', got %q", err.Error())
	}
}

func TestValidateOnly_AlreadyUsedToken(t *testing.T) {
	mgr, db := setupManager(t, 30*time.Minute)

	token, err := mgr.Generate("user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.MarkTokenAsUsed(hashToken(token)); err != nil {
		t.Fatal(err)
	}

	_, _, err = mgr.ValidateOnly(token)
	if err == nil {
		t.Fatal("expected error for already-used token")
	}
	if err.Error() != "token has already been used" {
		t.Errorf("expected 'token has already been used', got %q", err.Error())
	}
}

func TestCheckRateLimit_BelowAtAbove(t *testing.T) {
	mgr, _ := setupManager(t, 30*time.Minute)

	email := "user@example.com"
	window := 1 * time.Hour
	maxAttempts := 5

	// 4 tokens — below limit
	for i := 0; i < 4; i++ {
		if _, err := mgr.Generate(email); err != nil {
			t.Fatal(err)
		}
	}
	exceeded, err := mgr.CheckRateLimit(email, maxAttempts, window)
	if err != nil {
		t.Fatal(err)
	}
	if exceeded {
		t.Error("expected rate limit NOT exceeded with 4 tokens (limit 5)")
	}

	// 5th token — at limit (>=)
	if _, err := mgr.Generate(email); err != nil {
		t.Fatal(err)
	}
	exceeded, err = mgr.CheckRateLimit(email, maxAttempts, window)
	if err != nil {
		t.Fatal(err)
	}
	if !exceeded {
		t.Error("expected rate limit exceeded with 5 tokens (limit 5)")
	}

	// 6th token — above limit
	if _, err := mgr.Generate(email); err != nil {
		t.Fatal(err)
	}
	exceeded, err = mgr.CheckRateLimit(email, maxAttempts, window)
	if err != nil {
		t.Fatal(err)
	}
	if !exceeded {
		t.Error("expected rate limit exceeded with 6 tokens (limit 5)")
	}
}

func TestCheckRateLimit_OutsideWindow(t *testing.T) {
	mgr, _ := setupManager(t, 30*time.Minute)

	email := "user@example.com"
	if _, err := mgr.Generate(email); err != nil {
		t.Fatal(err)
	}

	// Wait so the token's created_at is comfortably in the past.
	time.Sleep(100 * time.Millisecond)

	// Window of 50ms — token is 100ms old, so it's outside the window.
	exceeded, err := mgr.CheckRateLimit(email, 1, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if exceeded {
		t.Error("expected rate limit NOT exceeded for token created outside window")
	}

	// Window of 1 hour — token is well within.
	exceeded, err = mgr.CheckRateLimit(email, 1, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !exceeded {
		t.Error("expected rate limit exceeded for token within window")
	}
}

func TestCleanupExpired(t *testing.T) {
	mgr, db := setupManager(t, 30*time.Minute)

	// Insert one expired and one valid token directly
	if err := db.SaveToken("expired", hashToken("expired"), "user@example.com", time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveToken("valid", hashToken("valid"), "user@example.com", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := mgr.CleanupExpired(); err != nil {
		t.Fatal(err)
	}

	// Expired should be gone
	expired, _, _, _, err := db.GetTokenByHash(hashToken("expired"))
	if err != nil {
		t.Fatal(err)
	}
	if expired != "" {
		t.Error("expected expired token to be removed")
	}

	// Valid should remain
	valid, _, _, _, err := db.GetTokenByHash(hashToken("valid"))
	if err != nil {
		t.Fatal(err)
	}
	if valid == "" {
		t.Error("expected valid token to be preserved")
	}
}
