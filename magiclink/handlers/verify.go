package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/naozine/nz-magic-link/magiclink/internal/session"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey string

// UserIDKey is the context key for the authenticated user ID.
const UserIDKey contextKey = "userID"

// VerifyHandler handles the verification of magic links.
// redirectURL is the success redirect URL.
// errorRedirectURL is the error redirect URL used when verification fails or token is missing.
func VerifyHandler(tokenManager *token.Manager, sessionManager *session.Manager, redirectURL string, errorRedirectURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Helper: choose an effective error redirect (allow query override if valid)
		effectiveErrorRedirect := func(defaultURL string) string {
			override := r.URL.Query().Get("error_redirect")
			if override != "" {
				u, err := url.Parse(override)
				if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
					return override
				}
			}
			return defaultURL
		}(errorRedirectURL)

		// Get the token from the query string
		tokenValue := r.URL.Query().Get("token")
		if tokenValue == "" {
			code, httpStatus, desc := mapError("Token is required")
			if effectiveErrorRedirect != "" {
				http.Redirect(w, r, buildErrorRedirectURL(effectiveErrorRedirect, code, desc, httpStatus), http.StatusFound)
				return
			}
			writeJSON(w, httpStatus, ErrorResponse{Error: desc})
			return
		}

		// Validate the token (without marking as used)
		email, tokenHash, err := tokenManager.ValidateOnly(tokenValue)
		if err != nil {
			code, httpStatus, desc := mapError(err.Error())
			if effectiveErrorRedirect != "" {
				http.Redirect(w, r, buildErrorRedirectURL(effectiveErrorRedirect, code, desc, httpStatus), http.StatusFound)
				return
			}
			writeJSON(w, httpStatus, ErrorResponse{Error: desc})
			return
		}

		// Mark token as used and create session atomically
		if err := sessionManager.CreateWithTokenUsed(w, r, email, tokenHash); err != nil {
			code, httpStatus, desc := mapError(err.Error())
			if effectiveErrorRedirect != "" {
				http.Redirect(w, r, buildErrorRedirectURL(effectiveErrorRedirect, code, desc, httpStatus), http.StatusFound)
				return
			}
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: desc})
			return
		}

		// Redirect to the specified URL or return a success response
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
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
func AuthMiddleware(sessionManager *session.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Validate the session
			userID, authenticated, err := sessionManager.Validate(w, r)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{
					Error: "Failed to validate session",
				})
				return
			}

			if !authenticated {
				writeJSON(w, http.StatusUnauthorized, ErrorResponse{
					Error: "Unauthorized",
				})
				return
			}

			// Set the user ID in the request context
			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LogoutHandler handles user logout by invalidating the session.
// It accepts a redirectURL parameter to redirect the user after successful logout.
// The redirectURL can be overridden by a "redirect" query parameter.
func LogoutHandler(sessionManager *session.Manager, redirectURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Invalidate the session
		err := sessionManager.Invalidate(w, r)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to logout",
			})
			return
		}

		// Check if there's a redirect query parameter
		queryRedirect := r.URL.Query().Get("redirect")
		if queryRedirect != "" {
			// Override the default redirect URL with the query parameter
			redirectURL = queryRedirect
		}

		// Redirect to the specified URL or return a success response
		if redirectURL != "" {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"message": "Logged out successfully",
		})
	}
}
