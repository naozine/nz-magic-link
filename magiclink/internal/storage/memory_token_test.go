package storage

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func setupMemoryTokenStore(t *testing.T) (*MemoryTokenStore, *SQLiteDB) {
	t.Helper()
	inner := setupSQLite(t)
	m := NewMemoryTokenStore(inner, time.Hour) // long interval so cleanup doesn't interfere
	t.Cleanup(func() { m.Close() })
	return m, inner
}

func TestMemoryTokenStore_SaveAndGet(t *testing.T) {
	m, _ := setupMemoryTokenStore(t)

	err := m.SaveToken("rawtoken", "hash1", "user@example.com", time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	tok, email, expiresAt, used, err := m.GetTokenByHash("hash1")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "rawtoken" {
		t.Errorf("expected token 'rawtoken', got %q", tok)
	}
	if email != "user@example.com" {
		t.Errorf("expected email 'user@example.com', got %q", email)
	}
	if used {
		t.Error("expected used to be false")
	}
	if expiresAt.IsZero() {
		t.Error("expected non-zero expiresAt")
	}
}

func TestMemoryTokenStore_GetNonexistent(t *testing.T) {
	m, _ := setupMemoryTokenStore(t)

	tok, email, _, _, err := m.GetTokenByHash("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" || email != "" {
		t.Errorf("expected empty return for nonexistent token, got tok=%q email=%q", tok, email)
	}
}

func TestMemoryTokenStore_MarkAsUsed(t *testing.T) {
	m, _ := setupMemoryTokenStore(t)

	_ = m.SaveToken("tok", "hash2", "user@example.com", time.Now().Add(30*time.Minute))

	err := m.MarkTokenAsUsed("hash2")
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, used, _ := m.GetTokenByHash("hash2")
	if !used {
		t.Error("expected token to be marked as used")
	}
}

func TestMemoryTokenStore_MarkAsUsed_Nonexistent(t *testing.T) {
	m, _ := setupMemoryTokenStore(t)

	err := m.MarkTokenAsUsed("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}
}

func TestMemoryTokenStore_CountRecentTokens(t *testing.T) {
	m, _ := setupMemoryTokenStore(t)

	// Save 3 tokens for the same email
	for i := 0; i < 3; i++ {
		_ = m.SaveToken(fmt.Sprintf("tok%d", i), fmt.Sprintf("hash%d", i), "user@example.com", time.Now().Add(30*time.Minute))
	}
	// Save 1 token for a different email
	_ = m.SaveToken("other", "hash_other", "other@example.com", time.Now().Add(30*time.Minute))

	count, err := m.CountRecentTokens("user@example.com", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}

	// Count with future since should return 0
	count, err = m.CountRecentTokens("user@example.com", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}
}

func TestMemoryTokenStore_CleanupExpiredTokens(t *testing.T) {
	m, _ := setupMemoryTokenStore(t)

	// Save an expired token
	_ = m.SaveToken("expired", "hash_exp", "user@example.com", time.Now().Add(-time.Minute))
	// Save a valid token
	_ = m.SaveToken("valid", "hash_valid", "user@example.com", time.Now().Add(30*time.Minute))

	err := m.CleanupExpiredTokens()
	if err != nil {
		t.Fatal(err)
	}

	// Expired token should be gone
	tok, _, _, _, _ := m.GetTokenByHash("hash_exp")
	if tok != "" {
		t.Error("expected expired token to be cleaned up")
	}

	// Valid token should remain
	tok, _, _, _, _ = m.GetTokenByHash("hash_valid")
	if tok != "valid" {
		t.Error("expected valid token to remain")
	}
}

func TestMemoryTokenStore_MarkTokenUsedAndCreateSession(t *testing.T) {
	m, inner := setupMemoryTokenStore(t)

	_ = m.SaveToken("tok", "hash_combined", "user@example.com", time.Now().Add(30*time.Minute))

	err := m.MarkTokenUsedAndCreateSession("hash_combined", "sess-id", "sess-hash", "user@example.com", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("MarkTokenUsedAndCreateSession failed: %v", err)
	}

	// Token should be used in memory
	_, _, _, used, _ := m.GetTokenByHash("hash_combined")
	if !used {
		t.Error("expected token to be marked as used")
	}

	// Session should exist in the inner DB
	sessionID, userID, _, err := inner.GetSessionByHash("sess-hash")
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

func TestMemoryTokenStore_MarkTokenUsedAndCreateSession_Nonexistent(t *testing.T) {
	m, _ := setupMemoryTokenStore(t)

	err := m.MarkTokenUsedAndCreateSession("nonexistent", "sess-id", "sess-hash", "user@example.com", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("expected error for nonexistent token")
	}
}

func TestMemoryTokenStore_MarkTokenUsedAndCreateSession_SessionFailure(t *testing.T) {
	m, inner := setupMemoryTokenStore(t)

	_ = m.SaveToken("tok", "hash_revert", "user@example.com", time.Now().Add(30*time.Minute))

	// Pre-insert a session to cause UNIQUE constraint violation
	_ = inner.SaveSession("existing", "sess-hash-dup", "other@example.com", time.Now().Add(time.Hour))

	err := m.MarkTokenUsedAndCreateSession("hash_revert", "new-sess", "sess-hash-dup", "user@example.com", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("expected error due to duplicate session hash")
	}

	// Token used flag should be reverted
	_, _, _, used, _ := m.GetTokenByHash("hash_revert")
	if used {
		t.Error("expected token used flag to be reverted after session failure")
	}
}

func TestMemoryTokenStore_SessionDelegation(t *testing.T) {
	m, inner := setupMemoryTokenStore(t)

	// Save session through the memory store
	err := m.SaveSession("sess1", "shash1", "user@example.com", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	// Verify it exists in the inner DB
	sessionID, _, _, err := inner.GetSessionByHash("shash1")
	if err != nil {
		t.Fatal(err)
	}
	if sessionID != "sess1" {
		t.Errorf("expected session to be delegated to inner DB, got %q", sessionID)
	}
}

func TestMemoryTokenStore_ConcurrentAccess(t *testing.T) {
	m, _ := setupMemoryTokenStore(t)

	var wg sync.WaitGroup
	const goroutines = 100

	// Concurrent SaveToken + GetTokenByHash + CountRecentTokens
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hash := fmt.Sprintf("hash_%d", i)
			_ = m.SaveToken(fmt.Sprintf("tok_%d", i), hash, "user@example.com", time.Now().Add(30*time.Minute))
			_, _, _, _, _ = m.GetTokenByHash(hash)
			_, _ = m.CountRecentTokens("user@example.com", time.Now().Add(-time.Minute))
		}(i)
	}
	wg.Wait()

	// Verify all tokens exist
	count, _ := m.CountRecentTokens("user@example.com", time.Now().Add(-time.Minute))
	if count != goroutines {
		t.Errorf("expected %d tokens, got %d", goroutines, count)
	}
}
