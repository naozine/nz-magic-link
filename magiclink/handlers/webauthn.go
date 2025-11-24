package handlers

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	clientScriptFS embed.FS
}

// NewWebAuthnHandlers creates new WebAuthn handlers
func NewWebAuthnHandlers(webauthnService WebAuthnService, sessionMgr session.Manager, clientScriptFS embed.FS) *WebAuthnHandlers {
	return &WebAuthnHandlers{
		webauthn:       webauthnService,
		sessionManager: sessionMgr,
		clientScriptFS: clientScriptFS,
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
// Changed []byte to string to handle Base64URL encoded strings from JS client
type RawWebAuthnCredential struct {
	ID       string                   `json:"id"`
	RawID    string                   `json:"rawId"`
	Response RawAuthenticatorResponse `json:"response"`
	Type     string                   `json:"type"`
}

// RawAuthenticatorResponse represents the raw authenticator response
// Changed []byte to string
type RawAuthenticatorResponse struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

type LoginStartRequest struct {
	Email string `json:"email,omitempty"`
}

type LoginStartResponse struct {
	ChallengeID string                        `json:"challenge_id"`
	Options     *protocol.CredentialAssertion `json:"options"`
}

type LoginFinishRequest struct {
	ChallengeID string               `json:"challenge_id" validate:"required"`
	Response    RawWebAuthnAssertion `json:"response" validate:"required"`
}

// RawWebAuthnAssertion represents the raw assertion data from the client
// Changed []byte to string
type RawWebAuthnAssertion struct {
	ID       string                        `json:"id"`
	RawID    string                        `json:"rawId"`
	Response RawAuthenticatorAssertionResp `json:"response"`
	Type     string                        `json:"type"`
}

// RawAuthenticatorAssertionResp represents the raw authenticator assertion response
// Changed []byte to string
type RawAuthenticatorAssertionResp struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
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
	// Inputs are already Base64URL strings, so pass them directly
	webauthnResponse := map[string]interface{}{
		"id":    req.Response.ID,
		"rawId": req.Response.RawID,
		"response": map[string]interface{}{
			"attestationObject": req.Response.Response.AttestationObject,
			"clientDataJSON":    req.Response.Response.ClientDataJSON,
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
	c.Logger().Infof("LoginStart: Starting passkey authentication")

	var req LoginStartRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Errorf("LoginStart: Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
	}

	c.Logger().Infof("LoginStart: Request bound successfully - Email: %s", req.Email)

	var options *protocol.CredentialAssertion
	var challengeID string
	var err error

	if req.Email != "" {
		// User-identified login
		c.Logger().Infof("LoginStart: Using user-identified login for email: %s", req.Email)
		options, challengeID, err = h.webauthn.BeginLogin(req.Email)
	} else {
		// Discoverable login
		c.Logger().Infof("LoginStart: Using discoverable login (no email provided)")
		options, challengeID, err = h.webauthn.BeginDiscoverableLogin()
	}

	if err != nil {
		c.Logger().Errorf("LoginStart: Failed to start login: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start login",
		})
	}

	c.Logger().Infof("LoginStart: Login challenge created successfully - ChallengeID: %s", challengeID)

	// Convert WebAuthn options to browser-compatible format
	convertedOptions, err := convertCredentialAssertionForBrowser(options)
	if err != nil {
		c.Logger().Errorf("LoginStart: Failed to convert options for browser: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to prepare login options",
		})
	}

	response := map[string]interface{}{
		"challenge_id": challengeID,
		"options":      convertedOptions,
	}

	if responseBytes, err := json.Marshal(response); err == nil {
		c.Logger().Debugf("LoginStart: Response being sent to browser: %s", string(responseBytes))
	}

	return c.JSON(http.StatusOK, response)
}

// DiscoverableLoginStart handles the start of discoverable (userless) authentication
func (h *WebAuthnHandlers) DiscoverableLoginStart(c echo.Context) error {
	c.Logger().Infof("DiscoverableLoginStart: Starting discoverable (userless) authentication")

	options, challengeID, err := h.webauthn.BeginDiscoverableLogin()
	if err != nil {
		c.Logger().Errorf("DiscoverableLoginStart: Failed to start discoverable login: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start discoverable login",
		})
	}

	c.Logger().Infof("DiscoverableLoginStart: Discoverable login challenge created - ChallengeID: %s", challengeID)

	// Convert WebAuthn options to browser-compatible format
	convertedOptions, err := convertCredentialAssertionForBrowser(options)
	if err != nil {
		c.Logger().Errorf("DiscoverableLoginStart: Failed to convert options for browser: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to prepare discoverable login options",
		})
	}

	response := map[string]interface{}{
		"challenge_id": challengeID,
		"options":      convertedOptions,
	}

	if responseBytes, err := json.Marshal(response); err == nil {
		c.Logger().Debugf("DiscoverableLoginStart: Response being sent to browser: %s", string(responseBytes))
	}

	return c.JSON(http.StatusOK, response)
}

// LoginFinish handles the completion of passkey authentication
func (h *WebAuthnHandlers) LoginFinish(c echo.Context) error {
	c.Logger().Infof("LoginFinish: Starting passkey authentication completion")

	var req LoginFinishRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Errorf("LoginFinish: Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
	}

	c.Logger().Infof("LoginFinish: Request bound successfully - ChallengeID: %s", req.ChallengeID)

	// Validate required fields
	if req.ChallengeID == "" {
		c.Logger().Errorf("LoginFinish: Challenge ID is empty")
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Challenge ID is required",
		})
	}

	if req.Response.ID == "" {
		c.Logger().Errorf("LoginFinish: WebAuthn response ID is empty")
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "WebAuthn response is required",
		})
	}

	c.Logger().Infof("LoginFinish: Basic validation passed, converting WebAuthn response")

	// Convert the raw assertion data to the format expected by the WebAuthn library
	// Inputs are already Base64URL strings
	webauthnResponse := map[string]interface{}{
		"id":    req.Response.ID,
		"rawId": req.Response.RawID,
		"response": map[string]interface{}{
			"authenticatorData": req.Response.Response.AuthenticatorData,
			"clientDataJSON":    req.Response.Response.ClientDataJSON,
			"signature":         req.Response.Response.Signature,
		},
		"type": req.Response.Type,
	}

	// Add userHandle if present
	if req.Response.Response.UserHandle != "" {
		webauthnResponse["response"].(map[string]interface{})["userHandle"] = req.Response.Response.UserHandle
	}

	c.Logger().Infof("LoginFinish: Assertion data converted to proper format")

	// Convert to JSON bytes for parsing
	responseBytes, err := json.Marshal(webauthnResponse)
	if err != nil {
		c.Logger().Errorf("LoginFinish: Failed to marshal converted response: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Failed to process WebAuthn response",
		})
	}

	c.Logger().Debugf("LoginFinish: Converted response bytes: %s", string(responseBytes))

	// Parse the WebAuthn response
	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(responseBytes)
	if err != nil {
		c.Logger().Errorf("LoginFinish: Failed to parse converted WebAuthn response: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Failed to parse WebAuthn response",
		})
	}

	c.Logger().Infof("LoginFinish: WebAuthn response parsed successfully")

	// Complete login with WebAuthn service
	userID, err := h.webauthn.FinishLogin(req.ChallengeID, parsedResponse)
	if err != nil {
		c.Logger().Errorf("LoginFinish: FinishLogin failed: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to complete passkey authentication",
		})
	}

	c.Logger().Infof("LoginFinish: Authentication successful for user: %s", userID)

	// Create session for the authenticated user
	err = h.sessionManager.Create(c, userID)
	if err != nil {
		c.Logger().Errorf("LoginFinish: Failed to create session: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to create user session",
		})
	}

	c.Logger().Infof("LoginFinish: Session created successfully for user: %s", userID)

	c.Logger().Infof("LoginFinish: Passkey authentication completed successfully for user: %s", userID)

	return c.JSON(http.StatusOK, LoginFinishResponse{
		Success:     true,
		RedirectURL: "/dashboard", // Redirect to dashboard after successful login
	})
}

// ServeClientScript handles the request for the WebAuthn client script
func (h *WebAuthnHandlers) ServeClientScript(c echo.Context) error {
	data, err := h.clientScriptFS.ReadFile("static/webauthn.js")
	if err != nil {
		c.Logger().Errorf("ServeClientScript: Failed to read script file: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to load client script",
		})
	}
	return c.Blob(http.StatusOK, "application/javascript", data)
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

	// Client script
	webauthn.GET("/static/webauthn.js", h.ServeClientScript)

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

// convertCredentialAssertionForBrowser converts WebAuthn CredentialAssertion to browser-compatible format
func convertCredentialAssertionForBrowser(assertion *protocol.CredentialAssertion) (map[string]interface{}, error) {
	if assertion == nil {
		return nil, fmt.Errorf("assertion is nil")
	}

	// Convert allowCredentials to browser format
	allowCredentials := make([]map[string]interface{}, len(assertion.Response.AllowedCredentials))
	for i, cred := range assertion.Response.AllowedCredentials {
		allowCredentials[i] = map[string]interface{}{
			"id":         base64.RawURLEncoding.EncodeToString(cred.CredentialID), // base64 for browser compatibility
			"type":       cred.Type,
			"transports": cred.Transport,
		}
	}

	result := map[string]interface{}{
		"challenge":        base64.RawURLEncoding.EncodeToString(assertion.Response.Challenge),
		"timeout":          assertion.Response.Timeout,
		"rpId":             assertion.Response.RelyingPartyID,
		"allowCredentials": allowCredentials,
		"userVerification": assertion.Response.UserVerification,
	}

	return result, nil
}
