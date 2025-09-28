package handlers

import (
	"encoding/base64"
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
	ChallengeID string                `json:"challenge_id" validate:"required"`
	Response    RawWebAuthnCredential `json:"response" validate:"required"`
}

// RawWebAuthnCredential represents the raw credential data from the client
type RawWebAuthnCredential struct {
	ID       string                   `json:"id"`
	RawID    []byte                   `json:"rawId"`
	Response RawAuthenticatorResponse `json:"response"`
	Type     string                   `json:"type"`
}

// RawAuthenticatorResponse represents the raw authenticator response
type RawAuthenticatorResponse struct {
	AttestationObject []byte `json:"attestationObject"`
	ClientDataJSON    []byte `json:"clientDataJSON"`
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
	c.Logger().Infof("RegisterFinish: Starting passkey registration completion")

	var req RegisterFinishRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Errorf("RegisterFinish: Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
	}

	c.Logger().Infof("RegisterFinish: Request bound successfully - ChallengeID: %s", req.ChallengeID)

	// Validate required fields
	if req.ChallengeID == "" {
		c.Logger().Errorf("RegisterFinish: Challenge ID is empty")
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Challenge ID is required",
		})
	}

	if req.Response.ID == "" {
		c.Logger().Errorf("RegisterFinish: WebAuthn response ID is empty")
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "WebAuthn response is required",
		})
	}

	c.Logger().Infof("RegisterFinish: Basic validation passed, parsing WebAuthn response")

	c.Logger().Infof("RegisterFinish: Converting raw credential data to proper format")

	// Convert the raw credential data to the format expected by the WebAuthn library
	webauthnResponse := map[string]interface{}{
		"id":    req.Response.ID,
		"rawId": base64.RawURLEncoding.EncodeToString(req.Response.RawID),
		"response": map[string]interface{}{
			"attestationObject": base64.RawURLEncoding.EncodeToString(req.Response.Response.AttestationObject),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(req.Response.Response.ClientDataJSON),
		},
		"type": req.Response.Type,
	}

	c.Logger().Infof("RegisterFinish: Credential data converted to proper format")

	// Convert to JSON bytes for parsing
	responseBytes, err := json.Marshal(webauthnResponse)
	if err != nil {
		c.Logger().Errorf("RegisterFinish: Failed to marshal converted response: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Failed to process WebAuthn response",
		})
	}

	c.Logger().Debugf("RegisterFinish: Converted response bytes: %s", string(responseBytes))

	// Parse the WebAuthn response
	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(responseBytes)
	if err != nil {
		c.Logger().Errorf("RegisterFinish: Failed to parse converted WebAuthn response: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Failed to parse WebAuthn response",
		})
	}

	c.Logger().Infof("RegisterFinish: WebAuthn response parsed successfully")

	// Complete registration with WebAuthn service
	err = h.webauthn.FinishRegistration(req.ChallengeID, parsedResponse)
	if err != nil {
		c.Logger().Errorf("RegisterFinish: FinishRegistration failed: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to complete passkey registration",
		})
	}

	c.Logger().Infof("RegisterFinish: Passkey registration completed successfully - ChallengeID: %s", req.ChallengeID)

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

	// Debug routes (for development only)
	webauthn.GET("/debug/credentials/:email", h.DebugCredentials)
}

// DebugCredentials shows stored credentials for a user (development only)
func (h *WebAuthnHandlers) DebugCredentials(c echo.Context) error {
	email := c.Param("email")
	if email == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Email parameter is required",
		})
	}

	c.Logger().Infof("DebugCredentials: Retrieving credentials for user: %s", email)

	// This would need to be implemented in the WebAuthn service interface
	// For now, return a placeholder response
	return c.JSON(http.StatusOK, map[string]interface{}{
		"email":   email,
		"message": "Debug endpoint - check server logs for stored credential details",
		"note":    "This endpoint is for development only",
	})
}
