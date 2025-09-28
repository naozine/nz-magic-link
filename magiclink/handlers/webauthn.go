package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/labstack/echo/v4"
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
	webauthn       WebAuthnService
	sessionManager session.Manager
}

// NewWebAuthnHandlers creates new WebAuthn handlers
func NewWebAuthnHandlers(webauthnService WebAuthnService, sessionMgr session.Manager) *WebAuthnHandlers {
	return &WebAuthnHandlers{
		webauthn:       webauthnService,
		sessionManager: sessionMgr,
	}
}

// Request/Response types
type RegisterStartRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type RegisterStartResponse struct {
	ChallengeID string                       `json:"challenge_id"`
	Options     *protocol.CredentialCreation `json:"options"`
}

type RegisterFinishRequest struct {
	ChallengeID string      `json:"challenge_id" validate:"required"`
	Response    interface{} `json:"response" validate:"required"`
}

type LoginStartRequest struct {
	Email string `json:"email,omitempty"`
}

type LoginStartResponse struct {
	ChallengeID string                        `json:"challenge_id"`
	Options     *protocol.CredentialAssertion `json:"options"`
}

type LoginFinishRequest struct {
	ChallengeID string                                  `json:"challenge_id" validate:"required"`
	Response    *protocol.ParsedCredentialAssertionData `json:"response" validate:"required"`
}

type LoginFinishResponse struct {
	Success     bool   `json:"success"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

// Use existing ErrorResponse from login.go

// RegisterStart handles the start of passkey registration
func (h *WebAuthnHandlers) RegisterStart(c echo.Context) error {
	var req RegisterStartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
	}

	// Basic validation
	if req.Email == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Email is required",
		})
	}
	// Simple email validation
	parts := strings.Split(req.Email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || !strings.Contains(parts[1], ".") {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid email format",
		})
	}

	options, challengeID, err := h.webauthn.BeginRegistration(req.Email)
	if err != nil {
		// Log the actual error for debugging
		c.Logger().Errorf("BeginRegistration failed: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start registration",
		})
	}

	// Log successful response for debugging
	c.Logger().Infof("BeginRegistration successful - ChallengeID: %s", challengeID)

	return c.JSON(http.StatusOK, RegisterStartResponse{
		ChallengeID: challengeID,
		Options:     options,
	})
}

// RegisterFinish handles the completion of passkey registration
func (h *WebAuthnHandlers) RegisterFinish(c echo.Context) error {
	var req RegisterFinishRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
	}

	// Validate required fields
	if req.ChallengeID == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Challenge ID is required",
		})
	}

	if req.Response == nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "WebAuthn response is required",
		})
	}

	// Parse the WebAuthn response
	responseBytes, err := json.Marshal(req.Response)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid WebAuthn response format",
		})
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(responseBytes)
	if err != nil {
		c.Logger().Errorf("Failed to parse WebAuthn response: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Failed to parse WebAuthn response",
		})
	}

	// Complete registration with WebAuthn service
	err = h.webauthn.FinishRegistration(req.ChallengeID, parsedResponse)
	if err != nil {
		c.Logger().Errorf("FinishRegistration failed: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to complete passkey registration",
		})
	}

	c.Logger().Infof("FinishRegistration successful - ChallengeID: %s", req.ChallengeID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Passkey registration completed successfully",
	})
}

// LoginStart handles the start of passkey authentication
func (h *WebAuthnHandlers) LoginStart(c echo.Context) error {
	var req LoginStartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
	}

	var options *protocol.CredentialAssertion
	var challengeID string
	var err error

	if req.Email != "" {
		// User-identified login
		options, challengeID, err = h.webauthn.BeginLogin(req.Email)
	} else {
		// Discoverable login
		options, challengeID, err = h.webauthn.BeginDiscoverableLogin()
	}

	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start login",
		})
	}

	return c.JSON(http.StatusOK, LoginStartResponse{
		ChallengeID: challengeID,
		Options:     options,
	})
}

// DiscoverableLoginStart handles the start of discoverable (userless) authentication
func (h *WebAuthnHandlers) DiscoverableLoginStart(c echo.Context) error {
	options, challengeID, err := h.webauthn.BeginDiscoverableLogin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start discoverable login",
		})
	}

	return c.JSON(http.StatusOK, LoginStartResponse{
		ChallengeID: challengeID,
		Options:     options,
	})
}

// LoginFinish handles the completion of passkey authentication
func (h *WebAuthnHandlers) LoginFinish(c echo.Context) error {
	// For now, return a placeholder response
	// This would be implemented once the WebAuthn service API is stabilized
	return c.JSON(http.StatusNotImplemented, ErrorResponse{
		Error: "Passkey login finish is not yet implemented",
	})
}

// RegisterRoutes Helper method to register all WebAuthn routes
func (h *WebAuthnHandlers) RegisterRoutes(e *echo.Echo) {
	webauthn := e.Group("/webauthn")

	// Registration routes
	webauthn.POST("/register/start", h.RegisterStart)
	webauthn.POST("/register/finish", h.RegisterFinish)

	// Login routes
	webauthn.POST("/login/start", h.LoginStart)
	webauthn.POST("/login/finish", h.LoginFinish)
	webauthn.POST("/login/discoverable", h.DiscoverableLoginStart)
}
