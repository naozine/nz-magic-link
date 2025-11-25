// Package storage provides abstracted database operations for the magic link authentication system.
package storage

import (
	"database/sql"
	"fmt"
	"time"
)

// PasskeyCredential represents a WebAuthn credential stored in the database
type PasskeyCredential struct {
	ID              string    `json:"id"`               // base64url(credentialID) — 主キー
	UserID          string    `json:"user_id"`          // 既存ユーザー識別子（email）
	PublicKey       []byte    `json:"public_key"`       // COSE公開鍵のraw bytes
	SignCount       uint32    `json:"sign_count"`       // リプレイ防止用カウンター
	AAGUID          string    `json:"aaguid,omitempty"` // 認証器AAGUID（任意）
	AttestationType string    `json:"attestation_type"` // attestation形式
	Transports      []string  `json:"transports"`       // サポートされる転送方式
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// PasskeyChallenge represents a short-lived challenge for WebAuthn operations
type PasskeyChallenge struct {
	ID                     string    `json:"id"`                       // ランダム UUID
	UserID                 string    `json:"user_id,omitempty"`        // ユーザーID（登録時任意）
	Type                   string    `json:"type"`                     // "attestation" or "assertion"
	Challenge              string    `json:"challenge"`                // ランダムバイト（base64url）
	ExpiresAt              time.Time `json:"expires_at"`               // 失効時刻
	SessionDataJSON        string    `json:"session_data_json"`        // webauthn.SessionDataのJSON化
	RequestOptionsSnapshot string    `json:"request_options_snapshot"` // リクエストオプションのスナップショット
}

// Database defines the interface for all database implementations.
// This allows switching between different storage backends (SQLite, LevelDB, etc.)
type Database interface {
	// Init initializes the database (creates tables, indexes, etc.)
	Init() error

	// Close closes the database connection and cleans up resources
	Close() error

	// Token operations
	SaveToken(token, tokenHash, email string, expiresAt time.Time) error
	GetTokenByHash(tokenHash string) (token, email string, expiresAt time.Time, used bool, err error)
	MarkTokenAsUsed(tokenHash string) error
	CountRecentTokens(email string, since time.Time) (int, error)
	CleanupExpiredTokens() error

	// Session operations
	SaveSession(sessionID, sessionHash, userID string, expiresAt time.Time) error
	GetSessionByHash(sessionHash string) (sessionID, userID string, expiresAt time.Time, err error)
	UpdateSessionExpiry(sessionHash string, newExpiresAt time.Time) error
	DeleteSession(sessionHash string) error
	CleanupExpiredSessions() error

	// Passkey credential operations
	SavePasskeyCredential(cred *PasskeyCredential) error
	GetPasskeyCredentialByID(credentialID string) (*PasskeyCredential, error)
	GetPasskeyCredentialsByUserID(userID string) ([]*PasskeyCredential, error)
	DeletePasskeyCredential(credentialID string) error
	UpdatePasskeyCredentialSignCount(credentialID string, signCount uint32) error

	// Passkey challenge operations
	SavePasskeyChallenge(challenge *PasskeyChallenge) error
	GetPasskeyChallenge(challengeID string) (*PasskeyChallenge, error)
	DeletePasskeyChallenge(challengeID string) error
	CleanupExpiredPasskeyChallenges() error

	// Health check
	Ping() error
}

// Config holds configuration for database connections.
type Config struct {
	Type    string            `json:"type"`    // "sqlite", "leveldb", etc.
	Path    string            `json:"path"`    // file path for file-based databases
	Options map[string]string `json:"options"` // database-specific options
}

// DatabaseType represents supported database types.
type DatabaseType string

const (
	TypeSQLite  DatabaseType = "sqlite"
	TypeLevelDB DatabaseType = "leveldb"
)

// Factory creates database instances based on configuration.
type Factory struct{}

// NewFactory creates a new database factory.
func NewFactory() *Factory {
	return &Factory{}
}

// Create creates a new database instance based on the provided configuration.
func (f *Factory) Create(config Config) (Database, error) {
	switch DatabaseType(config.Type) {
	case TypeSQLite:
		return NewSQLiteDB(config)
	case TypeLevelDB:
		return NewLevelDB(config)
	default:
		return nil, &UnsupportedDatabaseError{Type: config.Type}
	}
}

// CreateWithDB creates a new database instance using an existing database connection.
// Currently only supports SQLite with *sql.DB.
func (f *Factory) CreateWithDB(config Config, db *sql.DB) (Database, error) {
	switch DatabaseType(config.Type) {
	case TypeSQLite:
		return NewSQLiteDBFromDB(db)
	default:
		return nil, fmt.Errorf("database injection is not supported for type: %s", config.Type)
	}
}

// UnsupportedDatabaseError is returned when an unsupported database type is requested.
type UnsupportedDatabaseError struct {
	Type string
}

func (e *UnsupportedDatabaseError) Error() string {
	return "unsupported database type: " + e.Type
}
