package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteDB implements the Database interface using SQLite.
type SQLiteDB struct {
	db *sql.DB
}

// NewSQLiteDB creates a new SQLite database instance.
func NewSQLiteDB(config Config) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite", config.Path)
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

// NewSQLiteDBFromDB creates a new SQLite database instance using an existing sql.DB connection.
func NewSQLiteDBFromDB(db *sql.DB) (*SQLiteDB, error) {
	if db == nil {
		return nil, fmt.Errorf("db connection cannot be nil")
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

	// Create passkey_credentials table
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS passkey_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			public_key BLOB NOT NULL,
			sign_count INTEGER NOT NULL DEFAULT 0,
			aaguid TEXT,
			attestation_type TEXT NOT NULL,
			transports TEXT NOT NULL, -- JSON array
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create passkey_credentials table: %w", err)
	}

	// Create passkey_challenges table
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS passkey_challenges (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			type TEXT NOT NULL,
			challenge TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			session_data_json TEXT NOT NULL,
			request_options_snapshot TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create passkey_challenges table: %w", err)
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_token_hash ON tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_session_hash ON sessions(session_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_token_expires ON tokens(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_session_expires ON sessions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id ON passkey_credentials(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires ON passkey_challenges(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_passkey_challenges_type ON passkey_challenges(type)`,
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

// SavePasskeyCredential saves a passkey credential to the database.
func (s *SQLiteDB) SavePasskeyCredential(cred *PasskeyCredential) error {
	transportsJSON, err := json.Marshal(cred.Transports)
	if err != nil {
		return fmt.Errorf("failed to marshal transports: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO passkey_credentials
		(id, user_id, public_key, sign_count, aaguid, attestation_type, transports, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cred.ID, cred.UserID, cred.PublicKey, cred.SignCount, cred.AAGUID,
		cred.AttestationType, string(transportsJSON), cred.CreatedAt, cred.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save passkey credential: %w", err)
	}
	return nil
}

// GetPasskeyCredentialByID retrieves a passkey credential by ID.
func (s *SQLiteDB) GetPasskeyCredentialByID(credentialID string) (*PasskeyCredential, error) {
	var cred PasskeyCredential
	var transportsJSON string

	err := s.db.QueryRow(`
		SELECT id, user_id, public_key, sign_count, aaguid, attestation_type, transports, created_at, updated_at
		FROM passkey_credentials WHERE id = ?`,
		credentialID,
	).Scan(&cred.ID, &cred.UserID, &cred.PublicKey, &cred.SignCount, &cred.AAGUID,
		&cred.AttestationType, &transportsJSON, &cred.CreatedAt, &cred.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get passkey credential: %w", err)
	}

	if err := json.Unmarshal([]byte(transportsJSON), &cred.Transports); err != nil {
		return nil, fmt.Errorf("failed to unmarshal transports: %w", err)
	}

	return &cred, nil
}

// GetPasskeyCredentialsByUserID retrieves all passkey credentials for a user.
func (s *SQLiteDB) GetPasskeyCredentialsByUserID(userID string) ([]*PasskeyCredential, error) {
	rows, err := s.db.Query(`
		SELECT id, user_id, public_key, sign_count, aaguid, attestation_type, transports, created_at, updated_at
		FROM passkey_credentials WHERE user_id = ? ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query passkey credentials: %w", err)
	}
	defer rows.Close()

	var credentials []*PasskeyCredential
	for rows.Next() {
		var cred PasskeyCredential
		var transportsJSON string

		err := rows.Scan(&cred.ID, &cred.UserID, &cred.PublicKey, &cred.SignCount, &cred.AAGUID,
			&cred.AttestationType, &transportsJSON, &cred.CreatedAt, &cred.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan passkey credential: %w", err)
		}

		if err := json.Unmarshal([]byte(transportsJSON), &cred.Transports); err != nil {
			return nil, fmt.Errorf("failed to unmarshal transports: %w", err)
		}

		credentials = append(credentials, &cred)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate passkey credentials: %w", err)
	}

	return credentials, nil
}

// DeletePasskeyCredential deletes a passkey credential.
func (s *SQLiteDB) DeletePasskeyCredential(credentialID string) error {
	_, err := s.db.Exec(`DELETE FROM passkey_credentials WHERE id = ?`, credentialID)
	if err != nil {
		return fmt.Errorf("failed to delete passkey credential: %w", err)
	}
	return nil
}

// UpdatePasskeyCredentialSignCount updates the sign count for a passkey credential.
func (s *SQLiteDB) UpdatePasskeyCredentialSignCount(credentialID string, signCount uint32) error {
	_, err := s.db.Exec(`
		UPDATE passkey_credentials SET sign_count = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
		signCount, credentialID,
	)
	if err != nil {
		return fmt.Errorf("failed to update passkey credential sign count: %w", err)
	}
	return nil
}

// SavePasskeyChallenge saves a passkey challenge to the database.
func (s *SQLiteDB) SavePasskeyChallenge(challenge *PasskeyChallenge) error {
	_, err := s.db.Exec(`
		INSERT INTO passkey_challenges
		(id, user_id, type, challenge, expires_at, session_data_json, request_options_snapshot)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		challenge.ID, challenge.UserID, challenge.Type, challenge.Challenge,
		challenge.ExpiresAt, challenge.SessionDataJSON, challenge.RequestOptionsSnapshot,
	)
	if err != nil {
		return fmt.Errorf("failed to save passkey challenge: %w", err)
	}
	return nil
}

// GetPasskeyChallenge retrieves a passkey challenge by ID.
func (s *SQLiteDB) GetPasskeyChallenge(challengeID string) (*PasskeyChallenge, error) {
	var challenge PasskeyChallenge

	err := s.db.QueryRow(`
		SELECT id, user_id, type, challenge, expires_at, session_data_json, request_options_snapshot
		FROM passkey_challenges WHERE id = ?`,
		challengeID,
	).Scan(&challenge.ID, &challenge.UserID, &challenge.Type, &challenge.Challenge,
		&challenge.ExpiresAt, &challenge.SessionDataJSON, &challenge.RequestOptionsSnapshot)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get passkey challenge: %w", err)
	}

	return &challenge, nil
}

// DeletePasskeyChallenge deletes a passkey challenge.
func (s *SQLiteDB) DeletePasskeyChallenge(challengeID string) error {
	_, err := s.db.Exec(`DELETE FROM passkey_challenges WHERE id = ?`, challengeID)
	if err != nil {
		return fmt.Errorf("failed to delete passkey challenge: %w", err)
	}
	return nil
}

// CleanupExpiredPasskeyChallenges removes expired passkey challenges.
func (s *SQLiteDB) CleanupExpiredPasskeyChallenges() error {
	_, err := s.db.Exec(`DELETE FROM passkey_challenges WHERE expires_at < datetime('now')`)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired passkey challenges: %w", err)
	}
	return nil
}

// Ping checks if the database connection is alive.
func (s *SQLiteDB) Ping() error {
	return s.db.Ping()
}

// UpdateSessionExpiry updates the expiry time of a session by its hash.
func (s *SQLiteDB) UpdateSessionExpiry(sessionHash string, newExpiresAt time.Time) error {
	_, err := s.db.Exec(`UPDATE sessions SET expires_at = ? WHERE session_hash = ?`, newExpiresAt, sessionHash)
	if err != nil {
		return fmt.Errorf("failed to update session expiry: %w", err)
	}
	return nil
}
