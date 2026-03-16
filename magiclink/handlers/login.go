// Package handlers provides HTTP handlers for the magic link authentication system.
package handlers

import (
	"fmt"
	"net/http"
	"net/mail"
	"path"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"

	"github.com/naozine/nz-magic-link/magiclink/internal/email"
	"github.com/naozine/nz-magic-link/magiclink/internal/emailcheck"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

// LoginRequest represents the request body for the login endpoint.
type LoginRequest struct {
	Email string `json:"email"`
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
func LoginHandler(tokenManager *token.Manager, emailSender *email.Sender, maxAttempts int, window time.Duration, devBypassEmails map[string]bool, devBypassPatterns []string, serverAddr string, verifyURL string, loginSuccessMessage string, allowLogin func(c echo.Context, email string) error, disableRateLimiting bool, emailChecker *emailcheck.Checker) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !disableRateLimiting {
			// Get the client IP address for rate limiting
			ip := c.RealIP()

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
				return c.JSON(http.StatusTooManyRequests, ErrorResponse{
					Error: "Too many requests. Please try again later.",
				})
			}
		}

		// Parse the request body
		var req LoginRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Invalid request body",
			})
		}

		// Validate the email
		if req.Email == "" {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Email is required",
			})
		}

		// Validate email format
		_, err := mail.ParseAddress(req.Email)
		if err != nil {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Invalid email format",
			})
		}

		// Check if login is allowed
		if allowLogin != nil {
			if err := allowLogin(c, req.Email); err != nil {
				return c.JSON(http.StatusForbidden, ErrorResponse{
					Error: err.Error(),
				})
			}
		}

		// Check email domain quality (blacklist, whitelist, MX)
		if emailChecker != nil && emailChecker.Check(req.Email) {
			return c.JSON(http.StatusOK, LoginResponse{
				Message: loginSuccessMessage,
			})
		}

		if !disableRateLimiting {
			// Check user-specific rate limit
			exceeded, err := tokenManager.CheckRateLimit(req.Email, maxAttempts, window)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, ErrorResponse{
					Error: "Failed to check rate limit",
				})
			}

			if exceeded {
				return c.JSON(http.StatusTooManyRequests, ErrorResponse{
					Error: fmt.Sprintf("Too many login attempts. Please try again after %d minutes.", int(window.Minutes())),
				})
			}
		}

		// Generate a token
		token0, err := tokenManager.Generate(req.Email)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to generate token",
			})
		}

		// Check if the email is in the bypass list (exact match or wildcard pattern)
		if isDevBypass(req.Email, devBypassEmails, devBypassPatterns) {
			// Construct the magic link
			magicLink := fmt.Sprintf("%s%s?token=%s", serverAddr, verifyURL, token0)

			// Return the magic link in the response
			return c.JSON(http.StatusOK, LoginResponse{
				Message:   "Development mode: Magic link generated",
				MagicLink: magicLink,
			})
		}

		// Send the magic link
		err = emailSender.SendMagicLink(req.Email, token0, int(tokenManager.TokenExpiry.Minutes()))
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to send magic link",
			})
		}

		// Return a success response
		return c.JSON(http.StatusOK, LoginResponse{
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
