package handlers

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"

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
	RawID    string                   `json:"rawId"`
	Response RawAuthenticatorResponse `json:"response"`
	Type     string                   `json:"type"`
}

// RawAuthenticatorResponse represents the raw authenticator response
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
type RawWebAuthnAssertion struct {
	ID       string                        `json:"id"`
	RawID    string                        `json:"rawId"`
	Response RawAuthenticatorAssertionResp `json:"response"`
	Type     string                        `json:"type"`
}

// RawAuthenticatorAssertionResp represents the raw authenticator assertion response
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

// RegisterStart handles the start of passkey registration
func (h *WebAuthnHandlers) RegisterStart(c echo.Context) error {
	var req RegisterStartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
	}

	if req.Email == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Email is required",
		})
	}

	if _, err := mail.ParseAddress(req.Email); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid email format",
		})
	}

	options, challengeID, err := h.webauthn.BeginRegistration(req.Email)
	if err != nil {
		c.Logger().Errorf("BeginRegistration failed: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start registration",
		})
	}

	c.Logger().Debugf("BeginRegistration successful - ChallengeID: %s", challengeID)

	return c.JSON(http.StatusOK, RegisterStartResponse{
		ChallengeID: challengeID,
		Options:     options,
	})
}

// RegisterFinish handles the completion of passkey registration
func (h *WebAuthnHandlers) RegisterFinish(c echo.Context) error {
	var req RegisterFinishRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Errorf("RegisterFinish: Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
	}

	if req.ChallengeID == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Challenge ID is required",
		})
	}

	if req.Response.ID == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "WebAuthn response is required",
		})
	}

	webauthnResponse := map[string]interface{}{
		"id":    req.Response.ID,
		"rawId": req.Response.RawID,
		"response": map[string]interface{}{
			"attestationObject": req.Response.Response.AttestationObject,
			"clientDataJSON":    req.Response.Response.ClientDataJSON,
		},
		"type": req.Response.Type,
	}

	responseBytes, err := json.Marshal(webauthnResponse)
	if err != nil {
		c.Logger().Errorf("RegisterFinish: Failed to marshal response: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Failed to process WebAuthn response",
		})
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(responseBytes)
	if err != nil {
		c.Logger().Errorf("RegisterFinish: Failed to parse WebAuthn response: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Failed to parse WebAuthn response",
		})
	}

	if err := h.webauthn.FinishRegistration(req.ChallengeID, parsedResponse); err != nil {
		c.Logger().Errorf("RegisterFinish: FinishRegistration failed: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to complete passkey registration",
		})
	}

	c.Logger().Infof("RegisterFinish: Passkey registration completed - ChallengeID: %s", req.ChallengeID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Passkey registration completed successfully",
	})
}

// LoginStart handles the start of passkey authentication
func (h *WebAuthnHandlers) LoginStart(c echo.Context) error {
	var req LoginStartRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Errorf("LoginStart: Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
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
		c.Logger().Errorf("LoginStart: Failed to start login: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start login",
		})
	}

	c.Logger().Debugf("LoginStart: Challenge created - ChallengeID: %s", challengeID)

	convertedOptions, err := convertCredentialAssertionForBrowser(options)
	if err != nil {
		c.Logger().Errorf("LoginStart: Failed to convert options for browser: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to prepare login options",
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"challenge_id": challengeID,
		"options":      convertedOptions,
	})
}

// DiscoverableLoginStart handles the start of discoverable (userless) authentication
func (h *WebAuthnHandlers) DiscoverableLoginStart(c echo.Context) error {
	options, challengeID, err := h.webauthn.BeginDiscoverableLogin()
	if err != nil {
		c.Logger().Errorf("DiscoverableLoginStart: Failed to start discoverable login: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to start discoverable login",
		})
	}

	c.Logger().Debugf("DiscoverableLoginStart: Challenge created - ChallengeID: %s", challengeID)

	convertedOptions, err := convertCredentialAssertionForBrowser(options)
	if err != nil {
		c.Logger().Errorf("DiscoverableLoginStart: Failed to convert options for browser: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to prepare discoverable login options",
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"challenge_id": challengeID,
		"options":      convertedOptions,
	})
}

// LoginFinish handles the completion of passkey authentication
func (h *WebAuthnHandlers) LoginFinish(c echo.Context) error {
	var req LoginFinishRequest
	if err := c.Bind(&req); err != nil {
		c.Logger().Errorf("LoginFinish: Failed to bind request: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Invalid request format",
		})
	}

	if req.ChallengeID == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Challenge ID is required",
		})
	}

	if req.Response.ID == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "WebAuthn response is required",
		})
	}

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

	if req.Response.Response.UserHandle != "" {
		webauthnResponse["response"].(map[string]interface{})["userHandle"] = req.Response.Response.UserHandle
	}

	responseBytes, err := json.Marshal(webauthnResponse)
	if err != nil {
		c.Logger().Errorf("LoginFinish: Failed to marshal response: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Failed to process WebAuthn response",
		})
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(responseBytes)
	if err != nil {
		c.Logger().Errorf("LoginFinish: Failed to parse WebAuthn response: %v", err)
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Failed to parse WebAuthn response",
		})
	}

	userID, err := h.webauthn.FinishLogin(req.ChallengeID, parsedResponse)
	if err != nil {
		c.Logger().Errorf("LoginFinish: FinishLogin failed: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to complete passkey authentication",
		})
	}

	if err := h.sessionManager.Create(c, userID); err != nil {
		c.Logger().Errorf("LoginFinish: Failed to create session: %v", err)
		return c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: "Failed to create user session",
		})
	}

	c.Logger().Infof("LoginFinish: Authentication completed for user: %s", userID)

	return c.JSON(http.StatusOK, LoginFinishResponse{
		Success:     true,
		RedirectURL: h.successRedirectURL,
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

// RegisterRoutes registers all WebAuthn routes
func (h *WebAuthnHandlers) RegisterRoutes(e *echo.Echo) {
	webauthn := e.Group("/webauthn")

	webauthn.POST("/register/start", h.RegisterStart)
	webauthn.POST("/register/finish", h.RegisterFinish)

	webauthn.POST("/login/start", h.LoginStart)
	webauthn.POST("/login/finish", h.LoginFinish)
	webauthn.POST("/login/discoverable", h.DiscoverableLoginStart)

	webauthn.GET("/static/webauthn.js", h.ServeClientScript)
}

// convertCredentialAssertionForBrowser converts WebAuthn CredentialAssertion to browser-compatible format
func convertCredentialAssertionForBrowser(assertion *protocol.CredentialAssertion) (map[string]interface{}, error) {
	if assertion == nil {
		return nil, fmt.Errorf("assertion is nil")
	}

	allowCredentials := make([]map[string]interface{}, len(assertion.Response.AllowedCredentials))
	for i, cred := range assertion.Response.AllowedCredentials {
		allowCredentials[i] = map[string]interface{}{
			"id":         base64.RawURLEncoding.EncodeToString(cred.CredentialID),
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
