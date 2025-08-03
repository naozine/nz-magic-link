// Package db provides database operations for the magic link authentication system.
package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB represents a database connection.
type DB struct {
	*sql.DB
}

// New creates a new database connection.
func New(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection parameters
	db.SetMaxOpenConns(1) // SQLite only supports one writer at a time
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	return &DB{db}, nil
}

// Init initializes the database schema.
func (db *DB) Init() error {
	// Create tokens table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			used BOOLEAN NOT NULL DEFAULT 0
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create tokens table: %w", err)
	}

	// Create sessions table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL UNIQUE,
			session_hash TEXT NOT NULL UNIQUE,
			user_id TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}

	// Create index on token_hash
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_token_hash ON tokens(token_hash)`)
	if err != nil {
		return fmt.Errorf("failed to create token_hash index: %w", err)
	}

	// Create index on session_hash
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_session_hash ON sessions(session_hash)`)
	if err != nil {
		return fmt.Errorf("failed to create session_hash index: %w", err)
	}

	// Create index on expires_at for tokens
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_token_expires ON tokens(expires_at)`)
	if err != nil {
		return fmt.Errorf("failed to create token expires index: %w", err)
	}

	// Create index on expires_at for sessions
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_session_expires ON sessions(expires_at)`)
	if err != nil {
		return fmt.Errorf("failed to create session expires index: %w", err)
	}

	return nil
}

// CleanupExpiredTokens removes expired tokens from the database.
func (db *DB) CleanupExpiredTokens() error {
	_, err := db.Exec(`DELETE FROM tokens WHERE expires_at < datetime('now')`)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	return nil
}

// CleanupExpiredSessions removes expired sessions from the database.
func (db *DB) CleanupExpiredSessions() error {
	_, err := db.Exec(`DELETE FROM sessions WHERE expires_at < datetime('now')`)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return nil
}

// SaveToken saves a token to the database.
func (db *DB) SaveToken(token, tokenHash, email string, expiresAt time.Time) error {
	_, err := db.Exec(
		`INSERT INTO tokens (token, token_hash, email, expires_at) VALUES (?, ?, ?, ?)`,
		token, tokenHash, email, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}
	return nil
}

// GetTokenByHash retrieves a token by its hash.
func (db *DB) GetTokenByHash(tokenHash string) (string, string, time.Time, bool, error) {
	var token, email string
	var expiresAt time.Time
	var used bool

	err := db.QueryRow(
		`SELECT token, email, expires_at, used FROM tokens WHERE token_hash = ?`,
		tokenHash,
	).Scan(&token, &email, &expiresAt, &used)

	if err == sql.ErrNoRows {
		return "", "", time.Time{}, false, nil
	}
	if err != nil {
		return "", "", time.Time{}, false, fmt.Errorf("failed to get token: %w", err)
	}

	return token, email, expiresAt, used, nil
}

// MarkTokenAsUsed marks a token as used.
func (db *DB) MarkTokenAsUsed(tokenHash string) error {
	_, err := db.Exec(`UPDATE tokens SET used = 1 WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}
	return nil
}

// SaveSession saves a session to the database.
func (db *DB) SaveSession(sessionID, sessionHash, userID string, expiresAt time.Time) error {
	_, err := db.Exec(
		`INSERT INTO sessions (session_id, session_hash, user_id, expires_at) VALUES (?, ?, ?, ?)`,
		sessionID, sessionHash, userID, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}
	return nil
}

// GetSessionByHash retrieves a session by its hash.
func (db *DB) GetSessionByHash(sessionHash string) (string, string, time.Time, error) {
	var sessionID, userID string
	var expiresAt time.Time

	err := db.QueryRow(
		`SELECT session_id, user_id, expires_at FROM sessions WHERE session_hash = ?`,
		sessionHash,
	).Scan(&sessionID, &userID, &expiresAt)

	if err == sql.ErrNoRows {
		return "", "", time.Time{}, nil
	}
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to get session: %w", err)
	}

	return sessionID, userID, expiresAt, nil
}

// DeleteSession deletes a session from the database.
func (db *DB) DeleteSession(sessionHash string) error {
	_, err := db.Exec(`DELETE FROM sessions WHERE session_hash = ?`, sessionHash)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// CountRecentTokens counts the number of tokens created for an email within a time window.
func (db *DB) CountRecentTokens(email string, since time.Time) (int, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM tokens WHERE email = ? AND created_at > ?`,
		email, since,
	).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to count recent tokens: %w", err)
	}

	return count, nil
}
