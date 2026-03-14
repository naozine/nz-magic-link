package storage

import (
	"fmt"
	"sync"
	"time"
)

type tokenEntry struct {
	token     string
	email     string
	createdAt time.Time
	expiresAt time.Time
	used      bool
}

// MemoryTokenStore implements the Database interface by storing tokens in memory
// and delegating all other operations (sessions, passkeys, etc.) to an inner Database.
type MemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*tokenEntry // key: tokenHash
	inner  Database
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewMemoryTokenStore creates a new MemoryTokenStore wrapping the given Database.
// It starts a background goroutine that cleans up expired tokens at the given interval.
func NewMemoryTokenStore(inner Database, cleanupInterval time.Duration) *MemoryTokenStore {
	m := &MemoryTokenStore{
		tokens: make(map[string]*tokenEntry),
		inner:  inner,
		stopCh: make(chan struct{}),
	}
	m.startCleanup(cleanupInterval)
	return m
}

func (m *MemoryTokenStore) startCleanup(interval time.Duration) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = m.CleanupExpiredTokens()
			case <-m.stopCh:
				return
			}
		}
	}()
}

// --- Token operations (in-memory) ---

func (m *MemoryTokenStore) SaveToken(token, tokenHash, email string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[tokenHash] = &tokenEntry{
		token:     token,
		email:     email,
		createdAt: time.Now(),
		expiresAt: expiresAt,
		used:      false,
	}
	return nil
}

func (m *MemoryTokenStore) GetTokenByHash(tokenHash string) (string, string, time.Time, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.tokens[tokenHash]
	if !ok {
		return "", "", time.Time{}, false, nil
	}
	return e.token, e.email, e.expiresAt, e.used, nil
}

func (m *MemoryTokenStore) MarkTokenAsUsed(tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.tokens[tokenHash]
	if !ok {
		return fmt.Errorf("failed to mark token as used: token not found")
	}
	e.used = true
	return nil
}

func (m *MemoryTokenStore) CountRecentTokens(email string, since time.Time) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, e := range m.tokens {
		if e.email == email && e.createdAt.After(since) {
			count++
		}
	}
	return count, nil
}

func (m *MemoryTokenStore) CleanupExpiredTokens() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for hash, e := range m.tokens {
		if now.After(e.expiresAt) {
			delete(m.tokens, hash)
		}
	}
	return nil
}

// MarkTokenUsedAndCreateSession marks a token as used in memory and saves the session to the inner DB.
// If SaveSession fails, the token's used flag is reverted.
func (m *MemoryTokenStore) MarkTokenUsedAndCreateSession(tokenHash, sessionID, sessionHash, userID string, expiresAt time.Time) error {
	m.mu.Lock()
	e, ok := m.tokens[tokenHash]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("failed to mark token as used: token not found")
	}
	e.used = true
	m.mu.Unlock()

	if err := m.inner.SaveSession(sessionID, sessionHash, userID, expiresAt); err != nil {
		// Revert token used flag
		m.mu.Lock()
		e.used = false
		m.mu.Unlock()
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}

// --- Delegated operations ---

func (m *MemoryTokenStore) Init() error  { return m.inner.Init() }
func (m *MemoryTokenStore) Ping() error  { return m.inner.Ping() }

func (m *MemoryTokenStore) Close() error {
	close(m.stopCh)
	m.wg.Wait()
	return m.inner.Close()
}

func (m *MemoryTokenStore) SaveSession(sessionID, sessionHash, userID string, expiresAt time.Time) error {
	return m.inner.SaveSession(sessionID, sessionHash, userID, expiresAt)
}
func (m *MemoryTokenStore) GetSessionByHash(sessionHash string) (string, string, time.Time, error) {
	return m.inner.GetSessionByHash(sessionHash)
}
func (m *MemoryTokenStore) UpdateSessionExpiry(sessionHash string, newExpiresAt time.Time) error {
	return m.inner.UpdateSessionExpiry(sessionHash, newExpiresAt)
}
func (m *MemoryTokenStore) DeleteSession(sessionHash string) error {
	return m.inner.DeleteSession(sessionHash)
}
func (m *MemoryTokenStore) CleanupExpiredSessions() error {
	return m.inner.CleanupExpiredSessions()
}

func (m *MemoryTokenStore) SavePasskeyCredential(cred *PasskeyCredential) error {
	return m.inner.SavePasskeyCredential(cred)
}
func (m *MemoryTokenStore) GetPasskeyCredentialByID(credentialID string) (*PasskeyCredential, error) {
	return m.inner.GetPasskeyCredentialByID(credentialID)
}
func (m *MemoryTokenStore) GetPasskeyCredentialsByUserID(userID string) ([]*PasskeyCredential, error) {
	return m.inner.GetPasskeyCredentialsByUserID(userID)
}
func (m *MemoryTokenStore) DeletePasskeyCredential(credentialID string) error {
	return m.inner.DeletePasskeyCredential(credentialID)
}
func (m *MemoryTokenStore) UpdatePasskeyCredentialSignCount(credentialID string, signCount uint32) error {
	return m.inner.UpdatePasskeyCredentialSignCount(credentialID, signCount)
}

func (m *MemoryTokenStore) SavePasskeyChallenge(challenge *PasskeyChallenge) error {
	return m.inner.SavePasskeyChallenge(challenge)
}
func (m *MemoryTokenStore) GetPasskeyChallenge(challengeID string) (*PasskeyChallenge, error) {
	return m.inner.GetPasskeyChallenge(challengeID)
}
func (m *MemoryTokenStore) DeletePasskeyChallenge(challengeID string) error {
	return m.inner.DeletePasskeyChallenge(challengeID)
}
func (m *MemoryTokenStore) CleanupExpiredPasskeyChallenges() error {
	return m.inner.CleanupExpiredPasskeyChallenges()
}

// Ensure MemoryTokenStore implements Database at compile time.
var _ Database = (*MemoryTokenStore)(nil)

