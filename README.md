# Magic Link Authentication for Go/Echo

A simple, secure passwordless authentication library for Go applications using the Echo web framework. This library provides magic link authentication via email, allowing users to sign in without passwords.

## Features

- **Passwordless Authentication**: Send magic links via email for secure, passwordless login
- **SQLite Storage**: Simple database setup with automatic schema creation
- **Secure by Default**: Implements security best practices for tokens and sessions
- **Rate Limiting**: Prevents abuse with configurable rate limits
- **Customizable**: Flexible configuration for tokens, sessions, and emails
- **Echo Integration**: Easy to integrate with Echo web applications

## Installation

```bash
go get github.com/yourusername/nz-magic-link
```

## Quick Start

```go
package main

import (
    "github.com/labstack/echo/v4"
    "github.com/yourusername/nz-magic-link/magiclink"
)

func main() {
    // Create a new Echo instance
    e := echo.New()

    // Create a default configuration
    config := magiclink.DefaultConfig()
    
    // Configure SMTP settings for sending emails
    config.SMTPHost = "smtp.example.com"
    config.SMTPPort = 587
    config.SMTPUsername = "your-email@example.com"
    config.SMTPPassword = "your-password"
    config.SMTPFrom = "your-email@example.com"
    config.SMTPFromName = "Your App Name"
    config.ServerAddr = "https://yourapp.com"  // Used for constructing magic links

    // Create a new MagicLink instance
    ml, err := magiclink.New(config)
    if err != nil {
        e.Logger.Fatal(err)
    }

    // Register the authentication handlers
    ml.RegisterHandlers(e)

    // Create a protected route
    protected := e.Group("/protected")
    protected.Use(ml.AuthMiddleware())
    protected.GET("", func(c echo.Context) error {
        userID, _ := ml.GetUserID(c)
        return c.String(200, "Hello, "+userID+"!")
    })

    // Start the server
    e.Logger.Fatal(e.Start(":8080"))
}
```

## Configuration

The library can be configured using the `Config` struct:

```go
config := magiclink.DefaultConfig()
```

### Database Configuration

- `DatabasePath`: Path to the SQLite database file (default: "magiclink.db")

### Email Configuration

- `SMTPHost`: SMTP server hostname
- `SMTPPort`: SMTP server port (default: 587)
- `SMTPUsername`: SMTP username for authentication
- `SMTPPassword`: SMTP password for authentication
- `SMTPFrom`: Email address to send from
- `SMTPFromName`: Name to display in the From field
- `EmailTemplate`: Custom email template (optional)
- `ServerAddr`: Server address for constructing magic links (default: "http://localhost:8080")

### Token Configuration

- `TokenExpiry`: How long tokens are valid for (default: 30 minutes)

### Session Configuration

- `SessionExpiry`: How long sessions are valid for (default: 7 days)
- `CookieName`: Name of the session cookie (default: "session")
- `CookieSecure`: Whether to set the Secure flag on cookies (default: true)
- `CookieHTTPOnly`: Whether to set the HttpOnly flag on cookies (default: true)
- `CookieSameSite`: SameSite policy for cookies (default: "lax")
- `CookieDomain`: Domain for cookies (optional)
- `CookiePath`: Path for cookies (default: "/")

### URL Configuration

- `LoginURL`: URL for the login endpoint (default: "/auth/login")
- `VerifyURL`: URL for the verification endpoint (default: "/auth/verify")
- `RedirectURL`: URL to redirect to after successful verification (default: "/")
- `LogoutRedirectURL`: URL to redirect to after successful logout (default: "/")

### Rate Limiting

- `MaxLoginAttempts`: Maximum number of login attempts per email within the window (default: 5)
- `RateLimitWindow`: Time window for rate limiting (default: 15 minutes)

## API Reference

### Creating a New Instance

```go
ml, err := magiclink.New(config)
```

### Registering Handlers

```go
ml.RegisterHandlers(e)
```

This registers the following endpoints:
- `POST /auth/login`: Accepts an email address and sends a magic link
- `GET /auth/verify`: Verifies a token from a magic link and creates a session
- `POST /auth/logout`: Logs out the user by invalidating their session and redirects to the configured URL. You can override the redirect URL by adding a `redirect` query parameter (e.g., `/auth/logout?redirect=/login`)

### Authentication Middleware

```go
e.Use(ml.AuthMiddleware())
```

### Getting the User ID

```go
userID, authenticated := ml.GetUserID(c)
```

### Logging Out

```go
ml.Logout(c)
```

### Cleaning Up Expired Tokens and Sessions

```go
ml.CleanupExpiredTokens()
ml.CleanupExpiredSessions()
```

## Security Considerations

- Tokens are cryptographically secure and hashed before storage
- Sessions use secure cookies with HttpOnly and SameSite flags
- Rate limiting prevents brute force attacks
- Tokens and sessions expire automatically

## License

MIT