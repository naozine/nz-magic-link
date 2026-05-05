package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// setupSQLite creates a temporary SQLite database for testing.
func setupSQLite(t *testing.T) *SQLiteDB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := NewSQLiteDB(Config{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMarkTokenUsedAndCreateSession_SQLite(t *testing.T) {
	db := setupSQLite(t)

	// Save a token
	tokenHash := "testhash123"
	err := db.SaveToken("rawtoken", tokenHash, "user@example.com", time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	// Execute the combined operation
	expiresAt := time.Now().Add(time.Hour)
	err = db.MarkTokenUsedAndCreateSession(tokenHash, "sess-id", "sess-hash", "user@example.com", expiresAt)
	if err != nil {
		t.Fatalf("MarkTokenUsedAndCreateSession failed: %v", err)
	}

	// Verify token is marked as used
	_, _, _, used, err := db.GetTokenByHash(tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("expected token to be marked as used")
	}

	// Verify session was created
	sessionID, userID, _, err := db.GetSessionByHash("sess-hash")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "sess-id" {
		t.Errorf("expected session ID 'sess-id', got %q", sessionID)
	}
	if userID != "user@example.com" {
		t.Errorf("expected user ID 'user@example.com', got %q", userID)
	}
}

func TestMarkTokenUsedAndCreateSession_SQLite_Atomicity(t *testing.T) {
	db := setupSQLite(t)

	// Save a token
	tokenHash := "testhash456"
	err := db.SaveToken("rawtoken2", tokenHash, "user@example.com", time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	// Pre-insert a session with the same session_hash to cause a UNIQUE constraint violation
	err = db.SaveSession("existing-sess", "sess-hash-dup", "other@example.com", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// Attempt the combined operation — session insert should fail due to duplicate session_hash
	err = db.MarkTokenUsedAndCreateSession(tokenHash, "new-sess", "sess-hash-dup", "user@example.com", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("expected error due to duplicate session_hash, got nil")
	}

	// Verify token is NOT marked as used (rollback)
	_, _, _, used, err := db.GetTokenByHash(tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if used {
		t.Error("expected token to NOT be marked as used after rollback")
	}
}

func TestPasskeyCredential_BackupFlags_SQLite(t *testing.T) {
	db := setupSQLite(t)

	now := time.Now()
	cred := &PasskeyCredential{
		ID:              "cred-1",
		UserID:          "user@example.com",
		PublicKey:       []byte("pubkey"),
		SignCount:       0,
		AAGUID:          "aaguid",
		AttestationType: "none",
		Transports:      []string{"internal"},
		BackupEligible:  true,
		BackupState:     true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := db.SavePasskeyCredential(cred); err != nil {
		t.Fatal(err)
	}

	// GetPasskeyCredentialByID
	got, err := db.GetPasskeyCredentialByID("cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.BackupEligible {
		t.Error("expected BackupEligible to be true")
	}
	if !got.BackupState {
		t.Error("expected BackupState to be true")
	}

	// GetPasskeyCredentialsByUserID
	creds, err := db.GetPasskeyCredentialsByUserID("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if !creds[0].BackupEligible {
		t.Error("expected BackupEligible to be true")
	}
	if !creds[0].BackupState {
		t.Error("expected BackupState to be true")
	}
}

func TestPasskeyCredential_BackupFlags_Default_SQLite(t *testing.T) {
	db := setupSQLite(t)

	now := time.Now()
	cred := &PasskeyCredential{
		ID:              "cred-2",
		UserID:          "user@example.com",
		PublicKey:       []byte("pubkey"),
		SignCount:       0,
		AAGUID:          "aaguid",
		AttestationType: "none",
		Transports:      []string{"internal"},
		// BackupEligible and BackupState not set (default false)
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := db.SavePasskeyCredential(cred); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetPasskeyCredentialByID("cred-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.BackupEligible {
		t.Error("expected BackupEligible to be false by default")
	}
	if got.BackupState {
		t.Error("expected BackupState to be false by default")
	}
}

func TestPasskeyCredential_Migration_SQLite(t *testing.T) {
	// Simulate an existing DB without backup columns by calling Init twice
	db := setupSQLite(t)

	// Init should be idempotent — calling it again should not fail
	if err := db.Init(); err != nil {
		t.Fatalf("second Init() failed: %v", err)
	}

	// Save and retrieve a credential to verify columns work after migration
	now := time.Now()
	cred := &PasskeyCredential{
		ID:              "cred-migrate",
		UserID:          "user@example.com",
		PublicKey:       []byte("pubkey"),
		SignCount:       0,
		AAGUID:          "aaguid",
		AttestationType: "none",
		Transports:      []string{"internal"},
		BackupEligible:  true,
		BackupState:     true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := db.SavePasskeyCredential(cred); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetPasskeyCredentialByID("cred-migrate")
	if err != nil {
		t.Fatal(err)
	}
	if !got.BackupEligible || !got.BackupState {
		t.Error("expected backup flags to be preserved after migration")
	}
}

// TestCleanupExpiredTokens_SQLite is a regression test for the timestamp comparison
// bug: previously timestamps were stored as TEXT in mixed formats so cleanup never
// removed anything. After switching to INTEGER (Unix epoch), this must pass.
func TestCleanupExpiredTokens_SQLite(t *testing.T) {
	db := setupSQLite(t)

	// Insert one expired and one valid token.
	if err := db.SaveToken("expired", "hash-expired", "user@example.com", time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveToken("valid", "hash-valid", "user@example.com", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := db.CleanupExpiredTokens(); err != nil {
		t.Fatal(err)
	}

	expired, _, _, _, err := db.GetTokenByHash("hash-expired")
	if err != nil {
		t.Fatal(err)
	}
	if expired != "" {
		t.Error("expected expired token to be removed")
	}

	valid, _, _, _, err := db.GetTokenByHash("hash-valid")
	if err != nil {
		t.Fatal(err)
	}
	if valid == "" {
		t.Error("expected valid token to be preserved")
	}
}

// TestCleanupExpiredSessions_SQLite — see TestCleanupExpiredTokens_SQLite for context.
func TestCleanupExpiredSessions_SQLite(t *testing.T) {
	db := setupSQLite(t)

	if err := db.SaveSession("sid-expired", "shash-expired", "user@example.com", time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveSession("sid-valid", "shash-valid", "user@example.com", time.Now().Add(1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := db.CleanupExpiredSessions(); err != nil {
		t.Fatal(err)
	}

	expiredID, _, _, err := db.GetSessionByHash("shash-expired")
	if err != nil {
		t.Fatal(err)
	}
	if expiredID != "" {
		t.Error("expected expired session to be removed")
	}

	validID, _, _, err := db.GetSessionByHash("shash-valid")
	if err != nil {
		t.Fatal(err)
	}
	if validID == "" {
		t.Error("expected valid session to be preserved")
	}
}

// TestCleanupExpiredPasskeyChallenges_SQLite — see TestCleanupExpiredTokens_SQLite for context.
func TestCleanupExpiredPasskeyChallenges_SQLite(t *testing.T) {
	db := setupSQLite(t)

	expired := &PasskeyChallenge{
		ID:                     "ch-expired",
		Type:                   "attestation",
		Challenge:              "challenge-expired",
		ExpiresAt:              time.Now().Add(-1 * time.Hour),
		SessionDataJSON:        "{}",
		RequestOptionsSnapshot: "{}",
	}
	valid := &PasskeyChallenge{
		ID:                     "ch-valid",
		Type:                   "assertion",
		Challenge:              "challenge-valid",
		ExpiresAt:              time.Now().Add(1 * time.Hour),
		SessionDataJSON:        "{}",
		RequestOptionsSnapshot: "{}",
	}
	if err := db.SavePasskeyChallenge(expired); err != nil {
		t.Fatal(err)
	}
	if err := db.SavePasskeyChallenge(valid); err != nil {
		t.Fatal(err)
	}

	if err := db.CleanupExpiredPasskeyChallenges(); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetPasskeyChallenge("ch-expired")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected expired challenge to be removed")
	}

	got, err = db.GetPasskeyChallenge("ch-valid")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("expected valid challenge to be preserved")
	}
}

// TestCountRecentTokens_SQLite is a regression test for the rate-limit counting bug.
// Previously CountRecentTokens always returned 0 due to mixed-format string comparison.
func TestCountRecentTokens_SQLite(t *testing.T) {
	db := setupSQLite(t)

	for i := 0; i < 3; i++ {
		hash := fmt.Sprintf("hash-%d", i)
		if err := db.SaveToken(fmt.Sprintf("tok-%d", i), hash, "user@example.com", time.Now().Add(30*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SaveToken("tok-other", "hash-other", "other@example.com", time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	// All three tokens for user@example.com should be counted within a generous window.
	count, err := db.CountRecentTokens("user@example.com", time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("expected count 3 within 1h window, got %d", count)
	}

	// Different email should have 1.
	count, err = db.CountRecentTokens("other@example.com", time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected count 1 for other email, got %d", count)
	}

	// Future "since" should yield 0 (nothing created after a future point).
	count, err = db.CountRecentTokens("user@example.com", time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected count 0 with future since, got %d", count)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
