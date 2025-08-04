package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteDB implements the Database interface using SQLite.
type SQLiteDB struct {
	db *sql.DB
}

// NewSQLiteDB creates a new SQLite database instance.
func NewSQLiteDB(config Config) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", config.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Set connection parameters
	db.SetMaxOpenConns(1) // SQLite only supports one writer at a time
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	// Apply configuration options
	for key, value := range config.Options {
		switch key {
		case "journal_mode":
			if _, err := db.Exec(fmt.Sprintf("PRAGMA journal_mode=%s", value)); err != nil {
				return nil, fmt.Errorf("failed to set journal_mode: %w", err)
			}
		case "synchronous":
			if _, err := db.Exec(fmt.Sprintf("PRAGMA synchronous=%s", value)); err != nil {
				return nil, fmt.Errorf("failed to set synchronous: %w", err)
			}
		case "cache_size":
			if _, err := db.Exec(fmt.Sprintf("PRAGMA cache_size=%s", value)); err != nil {
				return nil, fmt.Errorf("failed to set cache_size: %w", err)
			}
		case "temp_store":
			if _, err := db.Exec(fmt.Sprintf("PRAGMA temp_store=%s", value)); err != nil {
				return nil, fmt.Errorf("failed to set temp_store: %w", err)
			}
		}
	}

	return &SQLiteDB{db: db}, nil
}

// Init initializes the database schema.
func (s *SQLiteDB) Init() error {
	// Create tokens table
	_, err := s.db.Exec(`
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
	_, err = s.db.Exec(`
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

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_token_hash ON tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_session_hash ON sessions(session_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_token_expires ON tokens(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_session_expires ON sessions(expires_at)`,
	}

	for _, index := range indexes {
		if _, err := s.db.Exec(index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// Close closes the database connection.
func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

// SaveToken saves a token to the database.
func (s *SQLiteDB) SaveToken(token, tokenHash, email string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO tokens (token, token_hash, email, expires_at) VALUES (?, ?, ?, ?)`,
		token, tokenHash, email, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}
	return nil
}

// GetTokenByHash retrieves a token by its hash.
func (s *SQLiteDB) GetTokenByHash(tokenHash string) (string, string, time.Time, bool, error) {
	var token, email string
	var expiresAt time.Time
	var used bool

	err := s.db.QueryRow(
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
func (s *SQLiteDB) MarkTokenAsUsed(tokenHash string) error {
	_, err := s.db.Exec(`UPDATE tokens SET used = 1 WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return fmt.Errorf("failed to mark token as used: %w", err)
	}
	return nil
}

// CountRecentTokens counts the number of tokens created for an email within a time window.
func (s *SQLiteDB) CountRecentTokens(email string, since time.Time) (int, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM tokens WHERE email = ? AND created_at > ?`,
		email, since,
	).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to count recent tokens: %w", err)
	}

	return count, nil
}

// CleanupExpiredTokens removes expired tokens from the database.
func (s *SQLiteDB) CleanupExpiredTokens() error {
	_, err := s.db.Exec(`DELETE FROM tokens WHERE expires_at < datetime('now')`)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}
	return nil
}

// SaveSession saves a session to the database.
func (s *SQLiteDB) SaveSession(sessionID, sessionHash, userID string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (session_id, session_hash, user_id, expires_at) VALUES (?, ?, ?, ?)`,
		sessionID, sessionHash, userID, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save session: %w", err)
	}
	return nil
}

// GetSessionByHash retrieves a session by its hash.
func (s *SQLiteDB) GetSessionByHash(sessionHash string) (string, string, time.Time, error) {
	var sessionID, userID string
	var expiresAt time.Time

	err := s.db.QueryRow(
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
func (s *SQLiteDB) DeleteSession(sessionHash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE session_hash = ?`, sessionHash)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	return nil
}

// CleanupExpiredSessions removes expired sessions from the database.
func (s *SQLiteDB) CleanupExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < datetime('now')`)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return nil
}

// Ping checks if the database connection is alive.
func (s *SQLiteDB) Ping() error {
	return s.db.Ping()
}
