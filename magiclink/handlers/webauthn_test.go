package handlers

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/naozine/nz-magic-link/magiclink/internal/session"
)

// mockWebAuthnService implements WebAuthnService for testing.
type mockWebAuthnService struct {
	beginRegistrationFn  func(email string) (*protocol.CredentialCreation, string, error)
	finishRegistrationFn func(challengeID string, response *protocol.ParsedCredentialCreationData) error
	beginLoginFn         func(email string) (*protocol.CredentialAssertion, string, error)
	beginDiscoverableFn  func() (*protocol.CredentialAssertion, string, error)
	finishLoginFn        func(challengeID string, response *protocol.ParsedCredentialAssertionData) (string, error)
}

func (m *mockWebAuthnService) BeginRegistration(email string) (*protocol.CredentialCreation, string, error) {
	if m.beginRegistrationFn != nil {
		return m.beginRegistrationFn(email)
	}
	return &protocol.CredentialCreation{}, "challenge-id", nil
}

func (m *mockWebAuthnService) FinishRegistration(challengeID string, response *protocol.ParsedCredentialCreationData) error {
	if m.finishRegistrationFn != nil {
		return m.finishRegistrationFn(challengeID, response)
	}
	return nil
}

func (m *mockWebAuthnService) BeginLogin(email string) (*protocol.CredentialAssertion, string, error) {
	if m.beginLoginFn != nil {
		return m.beginLoginFn(email)
	}
	return &protocol.CredentialAssertion{}, "challenge-id", nil
}

func (m *mockWebAuthnService) BeginDiscoverableLogin() (*protocol.CredentialAssertion, string, error) {
	if m.beginDiscoverableFn != nil {
		return m.beginDiscoverableFn()
	}
	return &protocol.CredentialAssertion{}, "challenge-id", nil
}

func (m *mockWebAuthnService) FinishLogin(challengeID string, response *protocol.ParsedCredentialAssertionData) (string, error) {
	if m.finishLoginFn != nil {
		return m.finishLoginFn(challengeID, response)
	}
	return "user@example.com", nil
}

//go:embed testdata
var testFS embed.FS

func setupWebAuthnHandlers(t *testing.T, svc *mockWebAuthnService) *WebAuthnHandlers {
	t.Helper()
	db := newMockDB()
	sessMgr := session.New(db, session.Config{
		CookieName:     "session",
		CookieSecure:   false,
		CookieHTTPOnly: true,
		CookieSameSite: "lax",
		CookiePath:     "/",
		SessionExpiry:  time.Hour,
	})

	h := NewWebAuthnHandlers(svc, *sessMgr, testFS, "/dashboard")
	return h
}

func postJSONHandler(handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// --- RegisterStart tests ---

func TestRegisterStart_EmailRequired(t *testing.T) {
	h := setupWebAuthnHandlers(t, &mockWebAuthnService{})
	rec := postJSONHandler(h.RegisterStart, `{}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	var resp ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error != "Email is required" {
		t.Errorf("unexpected error: %q", resp.Error)
	}
}

func TestRegisterStart_InvalidEmail(t *testing.T) {
	h := setupWebAuthnHandlers(t, &mockWebAuthnService{})
	rec := postJSONHandler(h.RegisterStart, `{"email":"not-an-email"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	var resp ErrorResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error != "Invalid email format" {
		t.Errorf("unexpected error: %q", resp.Error)
	}
}

func TestRegisterStart_Success(t *testing.T) {
	svc := &mockWebAuthnService{
		beginRegistrationFn: func(email string) (*protocol.CredentialCreation, string, error) {
			if email != "user@example.com" {
				t.Errorf("unexpected email: %s", email)
			}
			return &protocol.CredentialCreation{}, "test-challenge-id", nil
		},
	}

	h := setupWebAuthnHandlers(t, svc)
	rec := postJSONHandler(h.RegisterStart, `{"email":"user@example.com"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp RegisterStartResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ChallengeID != "test-challenge-id" {
		t.Errorf("unexpected challenge ID: %q", resp.ChallengeID)
	}
}

func TestRegisterStart_ServiceError(t *testing.T) {
	svc := &mockWebAuthnService{
		beginRegistrationFn: func(email string) (*protocol.CredentialCreation, string, error) {
			return nil, "", fmt.Errorf("service error")
		},
	}

	h := setupWebAuthnHandlers(t, svc)
	rec := postJSONHandler(h.RegisterStart, `{"email":"user@example.com"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// --- RegisterFinish tests ---

func TestRegisterFinish_ChallengeIDRequired(t *testing.T) {
	h := setupWebAuthnHandlers(t, &mockWebAuthnService{})
	rec := postJSONHandler(h.RegisterFinish, `{"challenge_id":"","response":{}}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRegisterFinish_ResponseRequired(t *testing.T) {
	h := setupWebAuthnHandlers(t, &mockWebAuthnService{})
	rec := postJSONHandler(h.RegisterFinish, `{"challenge_id":"abc"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// --- LoginStart tests ---

func TestLoginStart_WithEmail(t *testing.T) {
	called := false
	svc := &mockWebAuthnService{
		beginLoginFn: func(email string) (*protocol.CredentialAssertion, string, error) {
			called = true
			if email != "user@example.com" {
				t.Errorf("unexpected email: %s", email)
			}
			return &protocol.CredentialAssertion{}, "login-challenge", nil
		},
	}

	h := setupWebAuthnHandlers(t, svc)
	rec := postJSONHandler(h.LoginStart, `{"email":"user@example.com"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Error("expected BeginLogin to be called")
	}
}

func TestLoginStart_Discoverable(t *testing.T) {
	called := false
	svc := &mockWebAuthnService{
		beginDiscoverableFn: func() (*protocol.CredentialAssertion, string, error) {
			called = true
			return &protocol.CredentialAssertion{}, "disc-challenge", nil
		},
	}

	h := setupWebAuthnHandlers(t, svc)
	rec := postJSONHandler(h.LoginStart, `{}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Error("expected BeginDiscoverableLogin to be called")
	}
}

func TestLoginStart_ServiceError(t *testing.T) {
	svc := &mockWebAuthnService{
		beginLoginFn: func(email string) (*protocol.CredentialAssertion, string, error) {
			return nil, "", fmt.Errorf("no credentials")
		},
	}

	h := setupWebAuthnHandlers(t, svc)
	rec := postJSONHandler(h.LoginStart, `{"email":"user@example.com"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

// --- DiscoverableLoginStart tests ---

func TestDiscoverableLoginStart_Success(t *testing.T) {
	svc := &mockWebAuthnService{
		beginDiscoverableFn: func() (*protocol.CredentialAssertion, string, error) {
			return &protocol.CredentialAssertion{}, "disc-challenge", nil
		},
	}

	h := setupWebAuthnHandlers(t, svc)
	rec := postJSONHandler(h.DiscoverableLoginStart, `{}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// --- LoginFinish tests ---

func TestLoginFinish_ChallengeIDRequired(t *testing.T) {
	h := setupWebAuthnHandlers(t, &mockWebAuthnService{})
	rec := postJSONHandler(h.LoginFinish, `{"challenge_id":"","response":{}}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestLoginFinish_ResponseRequired(t *testing.T) {
	h := setupWebAuthnHandlers(t, &mockWebAuthnService{})
	rec := postJSONHandler(h.LoginFinish, `{"challenge_id":"abc"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestLoginFinish_InvalidResponse(t *testing.T) {
	h := setupWebAuthnHandlers(t, &mockWebAuthnService{})
	// Invalid WebAuthn assertion data — should fail at parse stage
	body := `{"challenge_id":"abc","response":{"id":"dGVzdA","rawId":"dGVzdA","type":"public-key","response":{"authenticatorData":"dGVzdA","clientDataJSON":"dGVzdA","signature":"dGVzdA"}}}`
	rec := postJSONHandler(h.LoginFinish, body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
