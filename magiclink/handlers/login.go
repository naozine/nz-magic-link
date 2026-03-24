// Package handlers provides HTTP handlers for the magic link authentication system.
package handlers

import (
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/naozine/nz-magic-link/magiclink/internal/email"
	"github.com/naozine/nz-magic-link/magiclink/internal/emailcheck"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

// LoginRequest represents the request body for the login endpoint.
type LoginRequest struct {
	Email    string `json:"email"`
	Redirect string `json:"redirect,omitempty"`
}

// LoginResponse represents the response body for the login endpoint.
type LoginResponse struct {
	Message   string `json:"message"`
	MagicLink string `json:"magic_link,omitempty"`
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// rateLimiters stores rate limiters for each IP address.
var (
	rateLimiters   = make(map[string]*rate.Limiter)
	rateLimitersMu sync.RWMutex
)

// LoginHandler handles the login request.
func LoginHandler(tokenManager *token.Manager, emailSender *email.Sender, maxAttempts int, window time.Duration, devBypassEmails map[string]bool, devBypassPatterns []string, serverAddr string, verifyURL string, loginSuccessMessage string, allowLogin func(r *http.Request, email string) error, disableRateLimiting bool, emailChecker *emailcheck.Checker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !disableRateLimiting {
			// Get the client IP address for rate limiting
			ip := realIP(r)

			// Check global rate limit (per IP)
			rateLimitersMu.RLock()
			limiter, exists := rateLimiters[ip]
			rateLimitersMu.RUnlock()

			if !exists {
				rateLimitersMu.Lock()
				limiter, exists = rateLimiters[ip]
				if !exists {
					// Allow 10 requests per minute per IP
					limiter = rate.NewLimiter(rate.Every(6*time.Second), 10)
					rateLimiters[ip] = limiter
				}
				rateLimitersMu.Unlock()
			}

			if !limiter.Allow() {
				writeJSON(w, http.StatusTooManyRequests, ErrorResponse{
					Error: "Too many requests. Please try again later.",
				})
				return
			}
		}

		// Parse the request body
		var req LoginRequest
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Invalid request body",
			})
			return
		}

		// Validate the email
		if req.Email == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Email is required",
			})
			return
		}

		// Validate email format
		_, err := mail.ParseAddress(req.Email)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Invalid email format",
			})
			return
		}

		// Check if login is allowed
		if allowLogin != nil {
			if err := allowLogin(r, req.Email); err != nil {
				writeJSON(w, http.StatusForbidden, ErrorResponse{
					Error: err.Error(),
				})
				return
			}
		}

		// Check email domain quality (blacklist, whitelist, MX)
		if emailChecker != nil && emailChecker.Check(req.Email) {
			writeJSON(w, http.StatusOK, LoginResponse{
				Message: loginSuccessMessage,
			})
			return
		}

		if !disableRateLimiting {
			// Check user-specific rate limit
			exceeded, err := tokenManager.CheckRateLimit(req.Email, maxAttempts, window)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, ErrorResponse{
					Error: "Failed to check rate limit",
				})
				return
			}

			if exceeded {
				writeJSON(w, http.StatusTooManyRequests, ErrorResponse{
					Error: fmt.Sprintf("Too many login attempts. Please try again after %d minutes.", int(window.Minutes())),
				})
				return
			}
		}

		// Validate redirect parameter (from body or query)
		redirectPath := req.Redirect
		if redirectPath == "" {
			redirectPath = safeRedirectPath(r, "redirect", "")
		} else {
			// Validate the redirect from the body using the same rules
			if !strings.HasPrefix(redirectPath, "/") || (len(redirectPath) > 1 && (redirectPath[1] == '/' || redirectPath[1] == '\\')) {
				redirectPath = ""
			} else {
				redirectPath = path.Clean(redirectPath)
				if redirectPath == "." {
					redirectPath = ""
				}
			}
		}

		// Generate a token
		token0, err := tokenManager.Generate(req.Email)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to generate token",
			})
			return
		}

		// Check if the email is in the bypass list (exact match or wildcard pattern)
		if isDevBypass(req.Email, devBypassEmails, devBypassPatterns) {
			// Construct the magic link
			magicLink := fmt.Sprintf("%s%s?token=%s", serverAddr, verifyURL, token0)
			if redirectPath != "" {
				magicLink += "&redirect=" + url.QueryEscape(redirectPath)
			}

			// Return the magic link in the response
			writeJSON(w, http.StatusOK, LoginResponse{
				Message:   "Development mode: Magic link generated",
				MagicLink: magicLink,
			})
			return
		}

		// Send the magic link
		err = emailSender.SendMagicLink(req.Email, token0, int(tokenManager.TokenExpiry.Minutes()), redirectPath)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to send magic link",
			})
			return
		}

		// Return a success response
		writeJSON(w, http.StatusOK, LoginResponse{
			Message: loginSuccessMessage,
		})
	}
}

// isDevBypass checks if the given email matches a bypass entry (exact match or wildcard pattern).
func isDevBypass(email string, exactMap map[string]bool, patterns []string) bool {
	if exactMap[email] {
		return true
	}
	for _, pattern := range patterns {
		if matched, _ := path.Match(pattern, email); matched {
			return true
		}
	}
	return false
}
