package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"nz-magic-link/magiclink/internal/session"
	"nz-magic-link/magiclink/internal/token"
)

// VerifyHandler handles the verification of magic links.
func VerifyHandler(tokenManager *token.Manager, sessionManager *session.Manager, redirectURL string) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Get the token from the query string
		tokenValue := c.QueryParam("token")
		if tokenValue == "" {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Token is required",
			})
		}

		// Validate the token
		email, err := tokenManager.Validate(tokenValue)
		if err != nil {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: err.Error(),
			})
		}

		// Create a session for the user
		err = sessionManager.Create(c, email)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to create session",
			})
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
func LogoutHandler(sessionManager *session.Manager) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Invalidate the session
		err := sessionManager.Invalidate(c)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to logout",
			})
		}

		return c.JSON(http.StatusOK, map[string]string{
			"message": "Logged out successfully",
		})
	}
}