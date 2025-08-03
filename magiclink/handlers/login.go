// Package handlers provides HTTP handlers for the magic link authentication system.
package handlers

import (
	"fmt"
	"net/http"
	"net/mail"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"

	"github.com/naozine/nz-magic-link/magiclink/internal/email"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

// LoginRequest represents the request body for the login endpoint.
type LoginRequest struct {
	Email string `json:"email"`
}

// LoginResponse represents the response body for the login endpoint.
type LoginResponse struct {
	Message string `json:"message"`
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// rateLimiters stores rate limiters for each IP address.
var rateLimiters = make(map[string]*rate.Limiter)

// LoginHandler handles the login request.
func LoginHandler(tokenManager *token.Manager, emailSender *email.Sender, maxAttempts int, window time.Duration) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Get the client IP address for rate limiting
		ip := c.RealIP()

		// Check global rate limit (per IP)
		limiter, exists := rateLimiters[ip]
		if !exists {
			// Allow 10 requests per minute per IP
			limiter = rate.NewLimiter(rate.Every(6*time.Second), 10)
			rateLimiters[ip] = limiter
		}

		if !limiter.Allow() {
			return c.JSON(http.StatusTooManyRequests, ErrorResponse{
				Error: "Too many requests. Please try again later.",
			})
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

		// Generate a token
		token, err := tokenManager.Generate(req.Email)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to generate token",
			})
		}

		// Send the magic link
		err = emailSender.SendMagicLink(req.Email, token, int(tokenManager.TokenExpiry.Minutes()))
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to send magic link",
			})
		}

		// Return a success response
		return c.JSON(http.StatusOK, LoginResponse{
			Message: "Magic link sent to your email",
		})
	}
}
