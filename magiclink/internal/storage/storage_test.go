package storage

import (
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
	t.Cleanup(func() { db.Close() })
	return db
}

// setupLevelDB creates a temporary LevelDB database for testing.
func setupLevelDB(t *testing.T) *LevelDB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.leveldb")
	db, err := NewLevelDB(Config{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
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

func TestMarkTokenUsedAndCreateSession_LevelDB(t *testing.T) {
	db := setupLevelDB(t)

	// Save a token
	tokenHash := "testhash789"
	err := db.SaveToken("rawtoken3", tokenHash, "user@example.com", time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	// Execute the combined operation
	expiresAt := time.Now().Add(time.Hour)
	err = db.MarkTokenUsedAndCreateSession(tokenHash, "sess-id-ldb", "sess-hash-ldb", "user@example.com", expiresAt)
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
	sessionID, userID, _, err := db.GetSessionByHash("sess-hash-ldb")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "sess-id-ldb" {
		t.Errorf("expected session ID 'sess-id-ldb', got %q", sessionID)
	}
	if userID != "user@example.com" {
		t.Errorf("expected user ID 'user@example.com', got %q", userID)
	}
}

func TestMarkTokenUsedAndCreateSession_LevelDB_NonexistentToken(t *testing.T) {
	db := setupLevelDB(t)

	// Attempt with a token that doesn't exist
	err := db.MarkTokenUsedAndCreateSession("nonexistent", "sess-id", "sess-hash", "user@example.com", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("expected error for nonexistent token, got nil")
	}

	// Verify session was NOT created
	sessionID, _, _, err := db.GetSessionByHash("sess-hash")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "" {
		t.Error("expected no session to be created for nonexistent token")
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

func TestPasskeyCredential_BackupFlags_LevelDB(t *testing.T) {
	db := setupLevelDB(t)

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
		BackupState:     false,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := db.SavePasskeyCredential(cred); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetPasskeyCredentialByID("cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.BackupEligible {
		t.Error("expected BackupEligible to be true")
	}
	if got.BackupState {
		t.Error("expected BackupState to be false")
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

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
