// Package storage provides abstracted database operations for the magic link authentication system.
package storage

import (
	"time"
)

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
	DeleteSession(sessionHash string) error
	CleanupExpiredSessions() error

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

// UnsupportedDatabaseError is returned when an unsupported database type is requested.
type UnsupportedDatabaseError struct {
	Type string
}

func (e *UnsupportedDatabaseError) Error() string {
	return "unsupported database type: " + e.Type
}
