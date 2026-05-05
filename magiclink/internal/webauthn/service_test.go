package webauthn

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/naozine/nz-magic-link/magiclink/internal/storage"
)

// setupService creates a Service backed by a temporary SQLite database with sane test config.
func setupService(t *testing.T) (*Service, *storage.SQLiteDB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := storage.NewSQLiteDB(storage.Config{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := Config{
		RPID:               "localhost",
		RPName:             "Test",
		AllowedOrigins:     []string{"http://localhost:8080"},
		ChallengeTTL:       5 * time.Minute,
		Timeout:            60 * time.Second,
		UserVerification:   "preferred",
		RequireResidentKey: false,
	}
	svc, err := NewService(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	return svc, db
}

// makeTestCredential constructs a PasskeyCredential suitable for DB insertion.
// The credentialID is the raw bytes; it gets base64-encoded into PasskeyCredential.ID.
func makeTestCredential(userID string, credentialID []byte) *storage.PasskeyCredential {
	return &storage.PasskeyCredential{
		ID:              base64.RawURLEncoding.EncodeToString(credentialID),
		UserID:          userID,
		PublicKey:       []byte("fake-public-key"),
		SignCount:       0,
		AAGUID:          "",
		AttestationType: "none",
		Transports:      []string{"internal"},
		BackupEligible:  false,
		BackupState:     false,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

// --- Construction ---

func TestNewService(t *testing.T) {
	svc, _ := setupService(t)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.webauthn == nil {
		t.Error("expected underlying webauthn instance to be initialized")
	}
}

// --- CreateUser ---

func TestCreateUser_NoCredentials(t *testing.T) {
	svc, _ := setupService(t)

	user, err := svc.CreateUser("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.WebAuthnName() != "user@example.com" {
		t.Errorf("expected name user@example.com, got %q", user.WebAuthnName())
	}
	if user.WebAuthnDisplayName() != "user@example.com" {
		t.Errorf("expected display name user@example.com, got %q", user.WebAuthnDisplayName())
	}
	if len(user.WebAuthnCredentials()) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(user.WebAuthnCredentials()))
	}
}

func TestCreateUser_WithCredentials(t *testing.T) {
	svc, db := setupService(t)

	cred := makeTestCredential("user@example.com", []byte("cred-1"))
	if err := db.SavePasskeyCredential(cred); err != nil {
		t.Fatal(err)
	}

	user, err := svc.CreateUser("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(user.WebAuthnCredentials()) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(user.WebAuthnCredentials()))
	}
	got := user.WebAuthnCredentials()[0]
	if !bytes.Equal(got.ID, []byte("cred-1")) {
		t.Errorf("expected credential ID 'cred-1', got %q", got.ID)
	}
}

func TestCreateUser_DerivesUserIDFromEmail(t *testing.T) {
	svc, _ := setupService(t)

	u1, _ := svc.CreateUser("user@example.com")
	u2, _ := svc.CreateUser("user@example.com")
	u3, _ := svc.CreateUser("other@example.com")

	if !bytes.Equal(u1.WebAuthnID(), u2.WebAuthnID()) {
		t.Error("expected same email to produce same WebAuthnID (deterministic)")
	}
	if bytes.Equal(u1.WebAuthnID(), u3.WebAuthnID()) {
		t.Error("expected different emails to produce different WebAuthnIDs")
	}
	if len(u1.WebAuthnID()) == 0 {
		t.Error("expected non-empty WebAuthnID")
	}
}

// --- BeginRegistration ---

func TestBeginRegistration_SavesChallenge(t *testing.T) {
	svc, db := setupService(t)

	_, challengeID, err := svc.BeginRegistration("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if challengeID == "" {
		t.Fatal("expected non-empty challenge ID")
	}

	got, err := db.GetPasskeyChallenge(challengeID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected challenge to be saved")
	}
	if got.Type != "attestation" {
		t.Errorf("expected Type=attestation, got %q", got.Type)
	}
	if got.UserID != "user@example.com" {
		t.Errorf("expected UserID=user@example.com, got %q", got.UserID)
	}
	if got.Challenge == "" {
		t.Error("expected non-empty challenge value")
	}
	if got.SessionDataJSON == "" {
		t.Error("expected SessionDataJSON to be populated")
	}
}

func TestBeginRegistration_ChallengeHasTTL(t *testing.T) {
	svc, db := setupService(t)
	// svc was created with ChallengeTTL=5min in setupService

	_, challengeID, err := svc.BeginRegistration("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GetPasskeyChallenge(challengeID)
	if err != nil {
		t.Fatal(err)
	}
	expected := time.Now().Add(5 * time.Minute)
	if got.ExpiresAt.Sub(expected).Abs() > 10*time.Second {
		t.Errorf("expected ExpiresAt near %v, got %v", expected, got.ExpiresAt)
	}
}

// --- BeginLogin ---

func TestBeginLogin_NoCredentials_Error(t *testing.T) {
	svc, _ := setupService(t)

	_, _, err := svc.BeginLogin("user@example.com")
	if err == nil {
		t.Fatal("expected error when user has no credentials")
	}
	// Don't pin exact text, but it should mention "no passkey credentials"
}

func TestBeginLogin_SavesChallenge(t *testing.T) {
	svc, db := setupService(t)
	if err := db.SavePasskeyCredential(makeTestCredential("user@example.com", []byte("cred-1"))); err != nil {
		t.Fatal(err)
	}

	_, challengeID, err := svc.BeginLogin("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GetPasskeyChallenge(challengeID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected challenge to be saved")
	}
	if got.Type != "assertion" {
		t.Errorf("expected Type=assertion, got %q", got.Type)
	}
	if got.UserID != "user@example.com" {
		t.Errorf("expected UserID=user@example.com, got %q", got.UserID)
	}
}

// --- BeginDiscoverableLogin ---

func TestBeginDiscoverableLogin_SavesChallenge(t *testing.T) {
	svc, db := setupService(t)

	_, challengeID, err := svc.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	got, err := db.GetPasskeyChallenge(challengeID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected challenge to be saved")
	}
	if got.Type != "assertion" {
		t.Errorf("expected Type=assertion, got %q", got.Type)
	}
	if got.UserID != "" {
		t.Errorf("expected empty UserID for discoverable login, got %q", got.UserID)
	}
}

// --- FinishRegistration error paths ---
// (Cryptographic happy-path requires real authenticator; covered by integration tests.)

func TestFinishRegistration_ChallengeNotFound(t *testing.T) {
	svc, _ := setupService(t)

	err := svc.FinishRegistration("nonexistent-challenge-id", nil)
	if err == nil {
		t.Fatal("expected error for missing challenge")
	}
}

func TestFinishRegistration_ChallengeExpired(t *testing.T) {
	svc, db := setupService(t)

	expired := &storage.PasskeyChallenge{
		ID:                     "expired-challenge",
		UserID:                 "user@example.com",
		Type:                   "attestation",
		Challenge:              "irrelevant",
		ExpiresAt:              time.Now().Add(-1 * time.Hour),
		SessionDataJSON:        "{}",
		RequestOptionsSnapshot: "{}",
	}
	if err := db.SavePasskeyChallenge(expired); err != nil {
		t.Fatal(err)
	}

	err := svc.FinishRegistration("expired-challenge", nil)
	if err == nil {
		t.Fatal("expected error for expired challenge")
	}

	// Expired challenge should be deleted
	got, err := db.GetPasskeyChallenge("expired-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected expired challenge to be deleted")
	}
}

func TestFinishRegistration_WrongType(t *testing.T) {
	svc, db := setupService(t)

	wrongType := &storage.PasskeyChallenge{
		ID:                     "assertion-challenge",
		UserID:                 "user@example.com",
		Type:                   "assertion", // wrong type for registration
		Challenge:              "irrelevant",
		ExpiresAt:              time.Now().Add(5 * time.Minute),
		SessionDataJSON:        "{}",
		RequestOptionsSnapshot: "{}",
	}
	if err := db.SavePasskeyChallenge(wrongType); err != nil {
		t.Fatal(err)
	}

	err := svc.FinishRegistration("assertion-challenge", nil)
	if err == nil {
		t.Fatal("expected error for wrong challenge type")
	}
}

// --- FinishLogin error paths ---

func TestFinishLogin_ChallengeNotFound(t *testing.T) {
	svc, _ := setupService(t)

	_, err := svc.FinishLogin("nonexistent-challenge-id", nil)
	if err == nil {
		t.Fatal("expected error for missing challenge")
	}
}

func TestFinishLogin_ChallengeExpired(t *testing.T) {
	svc, db := setupService(t)

	expired := &storage.PasskeyChallenge{
		ID:                     "expired-login-challenge",
		UserID:                 "user@example.com",
		Type:                   "assertion",
		Challenge:              "irrelevant",
		ExpiresAt:              time.Now().Add(-1 * time.Hour),
		SessionDataJSON:        "{}",
		RequestOptionsSnapshot: "{}",
	}
	if err := db.SavePasskeyChallenge(expired); err != nil {
		t.Fatal(err)
	}

	_, err := svc.FinishLogin("expired-login-challenge", nil)
	if err == nil {
		t.Fatal("expected error for expired challenge")
	}

	got, err := db.GetPasskeyChallenge("expired-login-challenge")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected expired challenge to be deleted")
	}
}

func TestFinishLogin_WrongType(t *testing.T) {
	svc, db := setupService(t)

	wrongType := &storage.PasskeyChallenge{
		ID:                     "registration-challenge",
		UserID:                 "user@example.com",
		Type:                   "attestation", // wrong type for login
		Challenge:              "irrelevant",
		ExpiresAt:              time.Now().Add(5 * time.Minute),
		SessionDataJSON:        "{}",
		RequestOptionsSnapshot: "{}",
	}
	if err := db.SavePasskeyChallenge(wrongType); err != nil {
		t.Fatal(err)
	}

	_, err := svc.FinishLogin("registration-challenge", nil)
	if err == nil {
		t.Fatal("expected error for wrong challenge type")
	}
}

// --- findUserByCredentialID ---

func TestFindUserByCredentialID_Found(t *testing.T) {
	svc, db := setupService(t)
	rawID := []byte("test-credential-id")
	if err := db.SavePasskeyCredential(makeTestCredential("user@example.com", rawID)); err != nil {
		t.Fatal(err)
	}

	userID, err := svc.findUserByCredentialID(rawID)
	if err != nil {
		t.Fatal(err)
	}
	if userID != "user@example.com" {
		t.Errorf("expected user@example.com, got %q", userID)
	}
}

func TestFindUserByCredentialID_NotFound(t *testing.T) {
	svc, _ := setupService(t)

	_, err := svc.findUserByCredentialID([]byte("unknown-credential-id"))
	if err == nil {
		t.Fatal("expected error for unknown credential")
	}
}

// --- transports helpers ---

func TestTransportStrings(t *testing.T) {
	in := []protocol.AuthenticatorTransport{
		protocol.AuthenticatorTransport("internal"),
		protocol.AuthenticatorTransport("usb"),
	}
	got := transportStrings(in)
	if len(got) != 2 || got[0] != "internal" || got[1] != "usb" {
		t.Errorf("unexpected output: %v", got)
	}
}

func TestTransportProtocols_DefaultsWhenEmpty(t *testing.T) {
	got := transportProtocols(nil)
	if len(got) != 2 {
		t.Fatalf("expected 2 default transports, got %d", len(got))
	}
	if string(got[0]) != "internal" || string(got[1]) != "usb" {
		t.Errorf("unexpected defaults: %v", got)
	}
}

func TestTransportProtocols_RoundTrip(t *testing.T) {
	got := transportProtocols([]string{"nfc", "ble"})
	if len(got) != 2 || string(got[0]) != "nfc" || string(got[1]) != "ble" {
		t.Errorf("expected [nfc ble], got %v", got)
	}
}
