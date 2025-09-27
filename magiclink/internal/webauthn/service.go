// Package webauthn provides WebAuthn/Passkey authentication services
package webauthn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/naozine/nz-magic-link/magiclink/internal/storage"
)

// Config holds WebAuthn configuration
type Config struct {
	RPID               string        `json:"rp_id"`
	RPName             string        `json:"rp_name"`
	AllowedOrigins     []string      `json:"allowed_origins"`
	ChallengeTTL       time.Duration `json:"challenge_ttl"`
	Timeout            time.Duration `json:"timeout"`
	MetadataValidation bool          `json:"metadata_validation"`
	UserVerification   string        `json:"user_verification"`
	RequireResidentKey bool          `json:"require_resident_key"`
}

// Service provides WebAuthn operations
type Service struct {
	webauthn *webauthn.WebAuthn
	storage  storage.Database
	config   Config
}

// NewService creates a new WebAuthn service
func NewService(config Config, db storage.Database) (*Service, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: config.RPName,
		RPID:          config.RPID,
		RPOrigins:     config.AllowedOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.UserVerificationRequirement(config.UserVerification),
		},
	}

	wan, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn instance: %w", err)
	}

	return &Service{
		webauthn: wan,
		storage:  db,
		config:   config,
	}, nil
}

// User implements webauthn.User interface
type User struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *User) WebAuthnID() []byte {
	return u.id
}

func (u *User) WebAuthnName() string {
	return u.name
}

func (u *User) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (u *User) WebAuthnIcon() string {
	return ""
}

// CreateUser creates a WebAuthn user from email
func (s *Service) CreateUser(email string) (*User, error) {
	// Generate a stable user ID from email hash
	userID := []byte(email) // In production, use a hash like SHA-256(email)

	// Get existing credentials for the user
	credentials, err := s.getWebAuthnCredentials(email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}

	return &User{
		id:          userID,
		name:        email,
		displayName: email,
		credentials: credentials,
	}, nil
}

// BeginRegistration starts passkey registration (mediated)
func (s *Service) BeginRegistration(email string) (*protocol.CredentialCreation, string, error) {
	// Create or get user
	user, err := s.CreateUser(email)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	// Begin registration with WebAuthn
	creation, sessionData, err := s.webauthn.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin registration: %w", err)
	}

	// Generate challenge ID
	challengeID, err := s.generateChallengeID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate challenge ID: %w", err)
	}

	// Store challenge in database
	challenge := &storage.PasskeyChallenge{
		ID:                     challengeID,
		UserID:                 email,
		Type:                   "attestation",
		Challenge:              sessionData.Challenge,
		ExpiresAt:              time.Now().Add(s.config.ChallengeTTL),
		SessionDataJSON:        s.encodeSessionData(sessionData),
		RequestOptionsSnapshot: s.encodeCreationOptions(creation),
	}

	if err := s.storage.SavePasskeyChallenge(challenge); err != nil {
		return nil, "", fmt.Errorf("failed to save challenge: %w", err)
	}

	return creation, challengeID, nil
}

// FinishRegistration completes passkey registration
func (s *Service) FinishRegistration(challengeID string, response *protocol.ParsedCredentialCreationData) error {
	// Placeholder implementation - to be completed when WebAuthn API is stabilized
	return fmt.Errorf("passkey registration finish not yet implemented")
}

// BeginLogin starts passkey authentication
func (s *Service) BeginLogin(email string) (*protocol.CredentialAssertion, string, error) {
	// Placeholder implementation - to be completed when WebAuthn API is stabilized
	return nil, "", fmt.Errorf("passkey login not yet implemented")
}

// BeginDiscoverableLogin starts discoverable (userless) authentication
func (s *Service) BeginDiscoverableLogin() (*protocol.CredentialAssertion, string, error) {
	// Placeholder implementation - to be completed when WebAuthn API is stabilized
	return nil, "", fmt.Errorf("discoverable login not yet implemented")
}

// FinishLogin completes passkey authentication
func (s *Service) FinishLogin(challengeID string, response *protocol.ParsedCredentialAssertionData) (string, error) {
	// Placeholder implementation - to be completed when WebAuthn API is stabilized
	return "", fmt.Errorf("passkey login finish not yet implemented")
}

// Helper methods - placeholder implementations

func (s *Service) generateChallengeID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate challenge ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (s *Service) getWebAuthnCredentials(userID string) ([]webauthn.Credential, error) {
	storedCreds, err := s.storage.GetPasskeyCredentialsByUserID(userID)
	if err != nil {
		return nil, err
	}

	credentials := make([]webauthn.Credential, 0, len(storedCreds))
	for _, cred := range storedCreds {
		credID, err := base64.RawURLEncoding.DecodeString(cred.ID)
		if err != nil {
			continue // Skip invalid credentials
		}

		credentials = append(credentials, webauthn.Credential{
			ID:        credID,
			PublicKey: cred.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: cred.SignCount,
			},
			Transport: transportProtocols(cred.Transports),
		})
	}

	return credentials, nil
}

func transportStrings(transports []protocol.AuthenticatorTransport) []string {
	result := make([]string, len(transports))
	for i, t := range transports {
		result[i] = string(t)
	}
	return result
}

func transportProtocols(transports []string) []protocol.AuthenticatorTransport {
	result := make([]protocol.AuthenticatorTransport, len(transports))
	for i, t := range transports {
		result[i] = protocol.AuthenticatorTransport(t)
	}
	return result
}

// encodeSessionData serializes WebAuthn session data to JSON
func (s *Service) encodeSessionData(sessionData *webauthn.SessionData) string {
	data, err := json.Marshal(sessionData)
	if err != nil {
		// Log error but don't fail the operation
		return "{}"
	}
	return string(data)
}

// encodeCreationOptions serializes credential creation options to JSON
func (s *Service) encodeCreationOptions(options *protocol.CredentialCreation) string {
	data, err := json.Marshal(options)
	if err != nil {
		// Log error but don't fail the operation
		return "{}"
	}
	return string(data)
}
