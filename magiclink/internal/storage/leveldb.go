package storage

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// LevelDB implements the Database interface using LevelDB.
type LevelDB struct {
	db *leveldb.DB
}

// TokenData represents token data structure for LevelDB storage.
type TokenData struct {
	Token     string    `json:"token"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// SessionData represents session data structure for LevelDB storage.
type SessionData struct {
	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Key prefixes for different data types
const (
	tokenPrefix        = "token:"
	sessionPrefix      = "session:"
	emailIndexPrefix   = "email_idx:"
	tokenCreatedPrefix = "token_created:"
)

// NewLevelDB creates a new LevelDB database instance.
func NewLevelDB(config Config) (*LevelDB, error) {
	// Set default options
	options := &opt.Options{
		BlockCacheCapacity:  16 * 1024 * 1024, // 16MB cache
		WriteBuffer:         8 * 1024 * 1024,  // 8MB write buffer
		CompactionTableSize: 4 * 1024 * 1024,  // 4MB table size
	}

	// Apply configuration options
	for key, value := range config.Options {
		switch key {
		case "block_cache_capacity":
			if size, err := strconv.Atoi(value); err == nil {
				options.BlockCacheCapacity = size
			}
		case "write_buffer":
			if size, err := strconv.Atoi(value); err == nil {
				options.WriteBuffer = size
			}
		case "compaction_table_size":
			if size, err := strconv.Atoi(value); err == nil {
				options.CompactionTableSize = size
			}
		}
	}

	db, err := leveldb.OpenFile(config.Path, options)
	if err != nil {
		return nil, fmt.Errorf("failed to open LevelDB: %w", err)
	}

	return &LevelDB{db: db}, nil
}

// Init initializes the database (no-op for LevelDB as it's schemaless).
func (l *LevelDB) Init() error {
	// LevelDB is schemaless, so no initialization needed
	// We could perform cleanup or validation here if needed
	return nil
}

// Close closes the database connection.
func (l *LevelDB) Close() error {
	return l.db.Close()
}

// SaveToken saves a token to the database.
func (l *LevelDB) SaveToken(token, tokenHash, email string, expiresAt time.Time) error {
	tokenData := TokenData{
		Token:     token,
		Email:     email,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Used:      false,
	}

	data, err := json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("failed to marshal token data: %w", err)
	}

	batch := new(leveldb.Batch)

	// Store main token data
	tokenKey := tokenPrefix + tokenHash
	batch.Put([]byte(tokenKey), data)

	// Store email index for CountRecentTokens
	emailIndexKey := emailIndexPrefix + email + ":" + strconv.FormatInt(tokenData.CreatedAt.Unix(), 10) + ":" + tokenHash
	batch.Put([]byte(emailIndexKey), []byte(tokenHash))

	// Store creation time index for cleanup
	createdKey := tokenCreatedPrefix + strconv.FormatInt(expiresAt.Unix(), 10) + ":" + tokenHash
	batch.Put([]byte(createdKey), []byte(tokenHash))

	err = l.db.Write(batch, nil)
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}

// GetTokenByHash retrieves a token by its hash.
func (l *LevelDB) GetTokenByHash(tokenHash string) (string, string, time.Time, bool, error) {
	tokenKey := tokenPrefix + tokenHash
	data, err := l.db.Get([]byte(tokenKey), nil)
	if err == leveldb.ErrNotFound {
		return "", "", time.Time{}, false, nil
	}
	if err != nil {
		return "", "", time.Time{}, false, fmt.Errorf("failed to get token: %w", err)
	}

	var tokenData TokenData
	if err := json.Unmarshal(data, &tokenData); err != nil {
		return "", "", time.Time{}, false, fmt.Errorf("failed to unmarshal token data: %w", err)
	}

	return tokenData.Token, tokenData.Email, tokenData.ExpiresAt, tokenData.Used, nil
}

// MarkTokenAsUsed marks a token as used.
func (l *LevelDB) MarkTokenAsUsed(tokenHash string) error {
	tokenKey := tokenPrefix + tokenHash
	data, err := l.db.Get([]byte(tokenKey), nil)
	if err != nil {
		return fmt.Errorf("failed to get token for update: %w", err)
	}

	var tokenData TokenData
	if err := json.Unmarshal(data, &tokenData); err != nil {
		return fmt.Errorf("failed to unmarshal token data: %w", err)
	}

	tokenData.Used = true

	newData, err := json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("failed to marshal updated token data: %w", err)
	}

	if err := l.db.Put([]byte(tokenKey), newData, nil); err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}

	return nil
}

// CountRecentTokens counts the number of tokens created for an email within a time window.
func (l *LevelDB) CountRecentTokens(email string, since time.Time) (int, error) {
	count := 0
	sinceUnix := since.Unix()
	prefix := emailIndexPrefix + email + ":"

	iter := l.db.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		parts := strings.Split(key, ":")
		if len(parts) >= 3 {
			if timestamp, err := strconv.ParseInt(parts[2], 10, 64); err == nil {
				if timestamp > sinceUnix {
					count++
				}
			}
		}
	}

	if err := iter.Error(); err != nil {
		return 0, fmt.Errorf("failed to count recent tokens: %w", err)
	}

	return count, nil
}

// CleanupExpiredTokens removes expired tokens from the database.
func (l *LevelDB) CleanupExpiredTokens() error {
	now := time.Now()
	batch := new(leveldb.Batch)

	// Find expired tokens using the creation time index
	prefix := tokenCreatedPrefix
	iter := l.db.NewIterator(util.BytesPrefix([]byte(prefix)), nil)
	defer iter.Release()

	for iter.Next() {
		key := string(iter.Key())
		parts := strings.Split(key, ":")
		if len(parts) >= 2 {
			if expiryTime, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				if now.Unix() > expiryTime {
					tokenHash := string(iter.Value())

					// Delete main token
					tokenKey := tokenPrefix + tokenHash
					batch.Delete([]byte(tokenKey))

					// Delete index entries (we'll clean these up broadly)
					batch.Delete(iter.Key())
				}
			}
		}
	}

	if err := iter.Error(); err != nil {
		return fmt.Errorf("failed to iterate expired tokens: %w", err)
	}

	// Clean up email index entries for expired tokens
	emailIter := l.db.NewIterator(util.BytesPrefix([]byte(emailIndexPrefix)), nil)
	defer emailIter.Release()

	for emailIter.Next() {
		tokenHash := string(emailIter.Value())
		tokenKey := tokenPrefix + tokenHash

		// Check if token still exists
		if _, err := l.db.Get([]byte(tokenKey), nil); err == leveldb.ErrNotFound {
			batch.Delete(emailIter.Key())
		}
	}

	if err := emailIter.Error(); err != nil {
		return fmt.Errorf("failed to cleanup email index: %w", err)
	}

	if err := l.db.Write(batch, nil); err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	return nil
}

// SaveSession saves a session to the database.
func (l *LevelDB) SaveSession(sessionID, sessionHash, userID string, expiresAt time.Time) error {
	sessionData := SessionData{
		SessionID: sessionID,
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	sessionKey := sessionPrefix + sessionHash
	if err := l.db.Put([]byte(sessionKey), data, nil); err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}

	return nil
}

// GetSessionByHash retrieves a session by its hash.
func (l *LevelDB) GetSessionByHash(sessionHash string) (string, string, time.Time, error) {
	sessionKey := sessionPrefix + sessionHash
	data, err := l.db.Get([]byte(sessionKey), nil)
	if err == leveldb.ErrNotFound {
		return "", "", time.Time{}, nil
	}
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to get session: %w", err)
	}

	var sessionData SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return sessionData.SessionID, sessionData.UserID, sessionData.ExpiresAt, nil
}

// DeleteSession deletes a session from the database.
func (l *LevelDB) DeleteSession(sessionHash string) error {
	sessionKey := sessionPrefix + sessionHash
	if err := l.db.Delete([]byte(sessionKey), nil); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// CleanupExpiredSessions removes expired sessions from the database.
func (l *LevelDB) CleanupExpiredSessions() error {
	now := time.Now()
	batch := new(leveldb.Batch)

	iter := l.db.NewIterator(util.BytesPrefix([]byte(sessionPrefix)), nil)
	defer iter.Release()

	for iter.Next() {
		var sessionData SessionData
		if err := json.Unmarshal(iter.Value(), &sessionData); err != nil {
			continue // Skip malformed data
		}

		if now.After(sessionData.ExpiresAt) {
			batch.Delete(iter.Key())
		}
	}

	if err := iter.Error(); err != nil {
		return fmt.Errorf("failed to iterate sessions for cleanup: %w", err)
	}

	if err := l.db.Write(batch, nil); err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	return nil
}

// Ping checks if the database is accessible.
func (l *LevelDB) Ping() error {
	// Try a simple operation to check if database is accessible
	_, err := l.db.Get([]byte("__ping__"), nil)
	if err != nil && err != leveldb.ErrNotFound {
		return fmt.Errorf("database ping failed: %w", err)
	}
	return nil
}
