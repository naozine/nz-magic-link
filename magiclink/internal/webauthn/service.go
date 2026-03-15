// Package webauthn provides WebAuthn/Passkey authentication services
package webauthn

import (
	"crypto/rand"
	"crypto/sha256"
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
			UserVerification:   protocol.UserVerificationRequirement(config.UserVerification),
			RequireResidentKey: &config.RequireResidentKey,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
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
	h := sha256.Sum256([]byte(email))
	userID := h[:]

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
	user, err := s.CreateUser(email)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	creation, sessionData, err := s.webauthn.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin registration: %w", err)
	}

	challengeID, err := s.generateChallengeID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate challenge ID: %w", err)
	}

	sessionJSON, err := s.encodeSessionData(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode session data: %w", err)
	}
	optionsJSON, err := s.encodeCreationOptions(creation)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode creation options: %w", err)
	}

	challenge := &storage.PasskeyChallenge{
		ID:                     challengeID,
		UserID:                 email,
		Type:                   "attestation",
		Challenge:              sessionData.Challenge,
		ExpiresAt:              time.Now().Add(s.config.ChallengeTTL),
		SessionDataJSON:        sessionJSON,
		RequestOptionsSnapshot: optionsJSON,
	}

	if err := s.storage.SavePasskeyChallenge(challenge); err != nil {
		return nil, "", fmt.Errorf("failed to save challenge: %w", err)
	}

	return creation, challengeID, nil
}

// FinishRegistration completes passkey registration
func (s *Service) FinishRegistration(challengeID string, response *protocol.ParsedCredentialCreationData) error {
	challenge, err := s.storage.GetPasskeyChallenge(challengeID)
	if err != nil {
		return fmt.Errorf("failed to get challenge: %w", err)
	}
	if challenge == nil {
		return fmt.Errorf("challenge not found: %s", challengeID)
	}

	if time.Now().After(challenge.ExpiresAt) {
		_ = s.storage.DeletePasskeyChallenge(challengeID)
		return fmt.Errorf("challenge has expired")
	}

	if challenge.Type != "attestation" {
		return fmt.Errorf("invalid challenge type for registration: %s", challenge.Type)
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(challenge.SessionDataJSON), &sessionData); err != nil {
		return fmt.Errorf("failed to decode session data: %w", err)
	}

	user, err := s.CreateUser(challenge.UserID)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	credential, err := s.webauthn.CreateCredential(user, sessionData, response)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	storedCred := &storage.PasskeyCredential{
		ID:              base64.RawURLEncoding.EncodeToString(credential.ID),
		UserID:          challenge.UserID,
		PublicKey:       credential.PublicKey,
		SignCount:       credential.Authenticator.SignCount,
		AAGUID:          base64.RawURLEncoding.EncodeToString(credential.Authenticator.AAGUID),
		AttestationType: credential.AttestationType,
		Transports:      transportStrings(credential.Transport),
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	if err := s.storage.SavePasskeyCredential(storedCred); err != nil {
		return fmt.Errorf("failed to save credential: %w", err)
	}

	_ = s.storage.DeletePasskeyChallenge(challengeID)

	return nil
}

// BeginLogin starts passkey authentication
func (s *Service) BeginLogin(email string) (*protocol.CredentialAssertion, string, error) {
	user, err := s.CreateUser(email)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create user: %w", err)
	}

	if len(user.credentials) == 0 {
		return nil, "", fmt.Errorf("no passkey credentials found for user %s", email)
	}

	assertion, sessionData, err := s.webauthn.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin login: %w", err)
	}

	challengeID, err := s.generateChallengeID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate challenge ID: %w", err)
	}

	sessionJSON, err := s.encodeSessionData(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode session data: %w", err)
	}
	optionsJSON, err := s.encodeAssertionOptions(assertion)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode assertion options: %w", err)
	}

	challenge := &storage.PasskeyChallenge{
		ID:                     challengeID,
		UserID:                 email,
		Type:                   "assertion",
		Challenge:              sessionData.Challenge,
		ExpiresAt:              time.Now().Add(s.config.ChallengeTTL),
		SessionDataJSON:        sessionJSON,
		RequestOptionsSnapshot: optionsJSON,
	}

	if err := s.storage.SavePasskeyChallenge(challenge); err != nil {
		return nil, "", fmt.Errorf("failed to save challenge: %w", err)
	}

	return assertion, challengeID, nil
}

// BeginDiscoverableLogin starts discoverable (userless) authentication
func (s *Service) BeginDiscoverableLogin() (*protocol.CredentialAssertion, string, error) {
	assertion, sessionData, err := s.webauthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("failed to begin discoverable login: %w", err)
	}

	challengeID, err := s.generateChallengeID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate challenge ID: %w", err)
	}

	sessionJSON, err := s.encodeSessionData(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode session data: %w", err)
	}
	optionsJSON, err := s.encodeAssertionOptions(assertion)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode assertion options: %w", err)
	}

	challenge := &storage.PasskeyChallenge{
		ID:                     challengeID,
		UserID:                 "",
		Type:                   "assertion",
		Challenge:              sessionData.Challenge,
		ExpiresAt:              time.Now().Add(s.config.ChallengeTTL),
		SessionDataJSON:        sessionJSON,
		RequestOptionsSnapshot: optionsJSON,
	}

	if err := s.storage.SavePasskeyChallenge(challenge); err != nil {
		return nil, "", fmt.Errorf("failed to save challenge: %w", err)
	}

	return assertion, challengeID, nil
}

// FinishLogin completes passkey authentication
func (s *Service) FinishLogin(challengeID string, response *protocol.ParsedCredentialAssertionData) (string, error) {
	challenge, err := s.storage.GetPasskeyChallenge(challengeID)
	if err != nil {
		return "", fmt.Errorf("failed to get challenge: %w", err)
	}
	if challenge == nil {
		return "", fmt.Errorf("challenge not found: %s", challengeID)
	}

	if time.Now().After(challenge.ExpiresAt) {
		_ = s.storage.DeletePasskeyChallenge(challengeID)
		return "", fmt.Errorf("challenge has expired")
	}

	if challenge.Type != "assertion" {
		return "", fmt.Errorf("invalid challenge type for login: %s", challenge.Type)
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(challenge.SessionDataJSON), &sessionData); err != nil {
		return "", fmt.Errorf("failed to decode session data: %w", err)
	}

	var credential *webauthn.Credential

	if challenge.UserID == "" {
		// Discoverable login: use ValidateDiscoverableLogin with a handler
		// that looks up the user by credential ID
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			userID, err := s.findUserByCredentialID(rawID)
			if err != nil {
				return nil, err
			}
			return s.CreateUser(userID)
		}

		var err error
		credential, err = s.webauthn.ValidateDiscoverableLogin(handler, sessionData, response)
		if err != nil {
			return "", fmt.Errorf("failed to validate discoverable login: %w", err)
		}

		// Find user ID for session creation
		foundUserID, err := s.findUserByCredentialID(response.RawID)
		if err != nil {
			return "", fmt.Errorf("failed to find user: %w", err)
		}
		challenge.UserID = foundUserID
	} else {
		// Regular login with known user
		user, err := s.CreateUser(challenge.UserID)
		if err != nil {
			return "", fmt.Errorf("failed to create user: %w", err)
		}

		if len(user.credentials) == 0 {
			return "", fmt.Errorf("no passkey credentials found for user %s", challenge.UserID)
		}

		credential, err = s.webauthn.ValidateLogin(user, sessionData, response)
		if err != nil {
			return "", fmt.Errorf("failed to validate login: %w", err)
		}
	}

	// Update credential sign count
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	_ = s.storage.UpdatePasskeyCredentialSignCount(credentialID, credential.Authenticator.SignCount)

	_ = s.storage.DeletePasskeyChallenge(challengeID)

	return challenge.UserID, nil
}

// Helper methods

func (s *Service) generateChallengeID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate challenge ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
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
			continue
		}

		var aaguid []byte
		if cred.AAGUID != "" {
			if decoded, err := base64.RawURLEncoding.DecodeString(cred.AAGUID); err == nil {
				aaguid = decoded
			}
		}

		credentials = append(credentials, webauthn.Credential{
			ID:        credID,
			PublicKey: cred.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: cred.SignCount,
				AAGUID:    aaguid,
			},
			Transport: transportProtocols(cred.Transports),
			Flags: webauthn.CredentialFlags{
				BackupEligible: cred.BackupEligible,
				BackupState:    cred.BackupState,
			},
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
	if len(transports) == 0 {
		return []protocol.AuthenticatorTransport{
			protocol.AuthenticatorTransport("internal"),
			protocol.AuthenticatorTransport("usb"),
		}
	}

	result := make([]protocol.AuthenticatorTransport, len(transports))
	for i, t := range transports {
		result[i] = protocol.AuthenticatorTransport(t)
	}
	return result
}

func (s *Service) encodeSessionData(sessionData *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}
	return string(data), nil
}

func (s *Service) encodeCreationOptions(options *protocol.CredentialCreation) (string, error) {
	data, err := json.Marshal(options)
	if err != nil {
		return "", fmt.Errorf("failed to marshal creation options: %w", err)
	}
	return string(data), nil
}

func (s *Service) encodeAssertionOptions(options *protocol.CredentialAssertion) (string, error) {
	data, err := json.Marshal(options)
	if err != nil {
		return "", fmt.Errorf("failed to marshal assertion options: %w", err)
	}
	return string(data), nil
}

func (s *Service) findUserByCredentialID(credentialID []byte) (string, error) {
	credentialIDStr := base64.RawURLEncoding.EncodeToString(credentialID)

	storedCred, err := s.storage.GetPasskeyCredentialByID(credentialIDStr)
	if err != nil {
		return "", fmt.Errorf("credential not found: %w", err)
	}
	if storedCred == nil {
		return "", fmt.Errorf("credential not found: %s", credentialIDStr)
	}

	return storedCred.UserID, nil
}
