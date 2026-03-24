package handlers

import (
	"embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/mail"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/naozine/nz-magic-link/magiclink/internal/session"
)

// WebAuthnService interface defines the WebAuthn operations needed by handlers
type WebAuthnService interface {
	BeginRegistration(email string) (*protocol.CredentialCreation, string, error)
	FinishRegistration(challengeID string, response *protocol.ParsedCredentialCreationData) error
	BeginLogin(email string) (*protocol.CredentialAssertion, string, error)
	BeginDiscoverableLogin() (*protocol.CredentialAssertion, string, error)
	FinishLogin(challengeID string, response *protocol.ParsedCredentialAssertionData) (string, error)
}

// WebAuthnHandlers contains all WebAuthn-related handlers
type WebAuthnHandlers struct {
	webauthn           WebAuthnService
	sessionManager     session.Manager
	clientScriptFS     embed.FS
	successRedirectURL string
}

// NewWebAuthnHandlers creates new WebAuthn handlers
func NewWebAuthnHandlers(webauthnService WebAuthnService, sessionMgr session.Manager, clientScriptFS embed.FS, successRedirectURL string) *WebAuthnHandlers {
	if successRedirectURL == "" {
		successRedirectURL = "/dashboard"
	}

	return &WebAuthnHandlers{
		webauthn:           webauthnService,
		sessionManager:     sessionMgr,
		clientScriptFS:     clientScriptFS,
		successRedirectURL: successRedirectURL,
	}
}

// Request/Response types

type RegisterStartRequest struct {
	Email string `json:"email"`
}

type RegisterStartResponse struct {
	ChallengeID string                      `json:"challenge_id"`
	Options     *protocol.CredentialCreation `json:"options"`
}

type RegisterFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Response    json.RawMessage `json:"response"`
}

type LoginStartRequest struct {
	Email string `json:"email,omitempty"`
}

type LoginStartResponse struct {
	ChallengeID string                       `json:"challenge_id"`
	Options     *protocol.CredentialAssertion `json:"options"`
}

type LoginFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Response    json.RawMessage `json:"response"`
}

type LoginFinishResponse struct {
	Success     bool   `json:"success"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

// RegisterStart handles the start of passkey registration
func (h *WebAuthnHandlers) RegisterStart(w http.ResponseWriter, r *http.Request) {
	var req RegisterStartRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
		return
	}

	if req.Email == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Email is required",
		})
		return
	}

	if _, err := mail.ParseAddress(req.Email); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Invalid email format",
		})
		return
	}

	options, challengeID, err := h.webauthn.BeginRegistration(req.Email)
	if err != nil {
		slog.Error("BeginRegistration failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start registration",
		})
		return
	}

	slog.Debug("BeginRegistration successful", "challenge_id", challengeID)

	writeJSON(w, http.StatusOK, RegisterStartResponse{
		ChallengeID: challengeID,
		Options:     options,
	})
}

// RegisterFinish handles the completion of passkey registration
func (h *WebAuthnHandlers) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	var req RegisterFinishRequest
	if err := readJSON(r, &req); err != nil {
		slog.Error("RegisterFinish: Failed to bind request", "error", err)
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
		return
	}

	if req.ChallengeID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Challenge ID is required",
		})
		return
	}

	if len(req.Response) == 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "WebAuthn response is required",
		})
		return
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(req.Response)
	if err != nil {
		slog.Error("RegisterFinish: Failed to parse WebAuthn response", "error", err)
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Failed to parse WebAuthn response",
		})
		return
	}

	if err := h.webauthn.FinishRegistration(req.ChallengeID, parsedResponse); err != nil {
		slog.Error("RegisterFinish: FinishRegistration failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to complete passkey registration",
		})
		return
	}

	slog.Info("RegisterFinish: Passkey registration completed", "challenge_id", req.ChallengeID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Passkey registration completed successfully",
	})
}

// LoginStart handles the start of passkey authentication
func (h *WebAuthnHandlers) LoginStart(w http.ResponseWriter, r *http.Request) {
	var req LoginStartRequest
	if err := readJSON(r, &req); err != nil {
		slog.Error("LoginStart: Failed to bind request", "error", err)
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
		return
	}

	var options *protocol.CredentialAssertion
	var challengeID string
	var err error

	if req.Email != "" {
		options, challengeID, err = h.webauthn.BeginLogin(req.Email)
	} else {
		options, challengeID, err = h.webauthn.BeginDiscoverableLogin()
	}

	if err != nil {
		slog.Error("LoginStart: Failed to start login", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start login",
		})
		return
	}

	slog.Debug("LoginStart: Challenge created", "challenge_id", challengeID)

	writeJSON(w, http.StatusOK, LoginStartResponse{
		ChallengeID: challengeID,
		Options:     options,
	})
}

// DiscoverableLoginStart handles the start of discoverable (userless) authentication
func (h *WebAuthnHandlers) DiscoverableLoginStart(w http.ResponseWriter, r *http.Request) {
	options, challengeID, err := h.webauthn.BeginDiscoverableLogin()
	if err != nil {
		slog.Error("DiscoverableLoginStart: Failed to start discoverable login", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start discoverable login",
		})
		return
	}

	slog.Debug("DiscoverableLoginStart: Challenge created", "challenge_id", challengeID)

	writeJSON(w, http.StatusOK, LoginStartResponse{
		ChallengeID: challengeID,
		Options:     options,
	})
}

// LoginFinish handles the completion of passkey authentication
func (h *WebAuthnHandlers) LoginFinish(w http.ResponseWriter, r *http.Request) {
	var req LoginFinishRequest
	if err := readJSON(r, &req); err != nil {
		slog.Error("LoginFinish: Failed to bind request", "error", err)
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
		return
	}

	if req.ChallengeID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Challenge ID is required",
		})
		return
	}

	if len(req.Response) == 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "WebAuthn response is required",
		})
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(req.Response)
	if err != nil {
		slog.Error("LoginFinish: Failed to parse WebAuthn response", "error", err)
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "Failed to parse WebAuthn response",
		})
		return
	}

	userID, err := h.webauthn.FinishLogin(req.ChallengeID, parsedResponse)
	if err != nil {
		slog.Error("LoginFinish: FinishLogin failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to complete passkey authentication",
		})
		return
	}

	if err := h.sessionManager.Create(w, r, userID); err != nil {
		slog.Error("LoginFinish: Failed to create session", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to create user session",
		})
		return
	}

	slog.Info("LoginFinish: Authentication completed", "user_id", userID)

	effectiveRedirect := safeRedirectPath(r, "redirect", h.successRedirectURL)

	writeJSON(w, http.StatusOK, LoginFinishResponse{
		Success:     true,
		RedirectURL: effectiveRedirect,
	})
}

// ServeClientScript handles the request for the WebAuthn client script
func (h *WebAuthnHandlers) ServeClientScript(w http.ResponseWriter, r *http.Request) {
	data, err := h.clientScriptFS.ReadFile("static/webauthn.js")
	if err != nil {
		slog.Error("ServeClientScript: Failed to read script file", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to load client script",
		})
		return
	}
	w.Header().Set("Content-Type", "application/javascript")
	w.Write(data)
}

// Handler returns an http.Handler that serves all WebAuthn routes.
func (h *WebAuthnHandlers) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /register/start", h.RegisterStart)
	mux.HandleFunc("POST /register/finish", h.RegisterFinish)

	mux.HandleFunc("POST /login/start", h.LoginStart)
	mux.HandleFunc("POST /login/finish", h.LoginFinish)
	mux.HandleFunc("POST /login/discoverable", h.DiscoverableLoginStart)

	mux.HandleFunc("GET /static/webauthn.js", h.ServeClientScript)

	return mux
}
