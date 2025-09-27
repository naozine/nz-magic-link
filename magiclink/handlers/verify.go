package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/naozine/nz-magic-link/magiclink/internal/session"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

// VerifyHandler handles the verification of magic links.
// redirectURL is the success redirect URL.
// errorRedirectURL is the error redirect URL used when verification fails or token is missing.
func VerifyHandler(tokenManager *token.Manager, sessionManager *session.Manager, redirectURL string, errorRedirectURL string) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Helper: choose an effective error redirect (allow query override if valid)
		effectiveErrorRedirect := func(defaultURL string) string {
			override := c.QueryParam("error_redirect")
			if override != "" {
				u, err := url.Parse(override)
				if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
					return override
				}
			}
			return defaultURL
		}(errorRedirectURL)

		// Get the token from the query string
		tokenValue := c.QueryParam("token")
		if tokenValue == "" {
			code, httpStatus, desc := mapError("Token is required")
			if effectiveErrorRedirect != "" {
				return c.Redirect(http.StatusFound, buildErrorRedirectURL(effectiveErrorRedirect, code, desc, httpStatus))
			}
			return c.JSON(httpStatus, ErrorResponse{Error: desc})
		}

		// Validate the token
		email, err := tokenManager.Validate(tokenValue)
		if err != nil {
			code, httpStatus, desc := mapError(err.Error())
			if effectiveErrorRedirect != "" {
				return c.Redirect(http.StatusFound, buildErrorRedirectURL(effectiveErrorRedirect, code, desc, httpStatus))
			}
			return c.JSON(httpStatus, ErrorResponse{Error: desc})
		}

		// Create a session for the user
		if err := sessionManager.Create(c, email); err != nil {
			code, httpStatus, desc := mapError("Failed to create session")
			if effectiveErrorRedirect != "" {
				return c.Redirect(http.StatusFound, buildErrorRedirectURL(effectiveErrorRedirect, code, desc, httpStatus))
			}
			return c.JSON(http.StatusInternalServerError, ErrorResponse{Error: desc})
		}

		// Redirect to the specified URL or return a success response
		if redirectURL != "" {
			return c.Redirect(http.StatusFound, redirectURL)
		}

		return c.JSON(http.StatusOK, map[string]string{
			"message": "Authentication successful",
			"email":   email,
		})
	}
}

// mapError converts error messages into a short error code, HTTP status, and description.
func mapError(errMsg string) (code string, httpStatus int, description string) {
	msg := strings.ToLower(errMsg)
	switch {
	case strings.Contains(msg, "token is required"):
		return "token_required", http.StatusBadRequest, "Token is required"
	case strings.Contains(msg, "invalid token"):
		return "invalid_token", http.StatusBadRequest, "invalid token"
	case strings.Contains(msg, "has expired"):
		return "token_expired", http.StatusBadRequest, "token has expired"
	case strings.Contains(msg, "already been used"):
		return "token_used", http.StatusBadRequest, "token has already been used"
	case strings.Contains(msg, "failed to get token") || strings.Contains(msg, "failed to mark token as used") || strings.Contains(msg, "failed to create session"):
		return "internal_error", http.StatusInternalServerError, "internal error"
	default:
		return "invalid_token", http.StatusBadRequest, errMsg
	}
}

// buildErrorRedirectURL appends error parameters to the given base URL.
func buildErrorRedirectURL(base string, code string, description string, httpCode int) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	q.Set("code", fmt.Sprintf("%d", httpCode))
	u.RawQuery = q.Encode()
	return u.String()
}

// AuthMiddleware creates a middleware that checks if the user is authenticated.
func AuthMiddleware(sessionManager *session.Manager) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Validate the session
			userID, authenticated, err := sessionManager.Validate(c)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, ErrorResponse{
					Error: "Failed to validate session",
				})
			}

			if !authenticated {
				return c.JSON(http.StatusUnauthorized, ErrorResponse{
					Error: "Unauthorized",
				})
			}

			// Set the user ID in the context
			c.Set("userID", userID)
			return next(c)
		}
	}
}

// LogoutHandler handles user logout by invalidating the session.
// It accepts a redirectURL parameter to redirect the user after successful logout.
// The redirectURL can be overridden by a "redirect" query parameter.
func LogoutHandler(sessionManager *session.Manager, redirectURL string) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Invalidate the session
		err := sessionManager.Invalidate(c)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to logout",
			})
		}

		// Check if there's a redirect query parameter
		queryRedirect := c.QueryParam("redirect")
		if queryRedirect != "" {
			// Override the default redirect URL with the query parameter
			redirectURL = queryRedirect
		}

		// Redirect to the specified URL or return a success response
		if redirectURL != "" {
			return c.Redirect(http.StatusFound, redirectURL)
		}

		return c.JSON(http.StatusOK, map[string]string{
			"message": "Logged out successfully",
		})
	}
}
