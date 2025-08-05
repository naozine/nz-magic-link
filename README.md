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
go get github.com/naozine/nz-magic-link
```

## Quick Start

For a complete working example, please refer to the [examples/simple](examples/simple) directory in the repository. This example demonstrates:

- Setting up an Echo server with the magic link authentication system
- Configuring SMTP settings for sending emails
- Creating public and protected routes
- Using HTML templates for login and dashboard pages
- Handling environment variables for configuration

Here's a brief overview of how to use the library:

1. Create a new Echo instance
2. Configure the MagicLink instance with your SMTP settings
3. Register the authentication handlers
4. Create protected routes using the authentication middleware
5. Start the server

The example in the repository provides a more comprehensive implementation that you can use as a starting point for your own application.

## Configuration

The library can be configured using the `Config` struct:

```
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

### Development Configuration

- `DevBypassEmailFilePath`: Path to a file containing email addresses that should bypass email sending. This is useful for development and testing purposes. The file should contain one email address per line. If an email address in this file requests a magic link, the link will be returned in the response instead of being sent via email, allowing for easier testing of the authentication flow.

## API Reference

### Creating a New Instance

```
ml, err := magiclink.New(config)
```

### Registering Handlers

```
ml.RegisterHandlers(e)
```

This registers the following endpoints:
- `POST /auth/login`: Accepts an email address and sends a magic link. If the email is in the bypass list (specified by `DevBypassEmailFilePath`), the magic link will be returned in the response as `magic_link` instead of being sent via email.
- `GET /auth/verify`: Verifies a token from a magic link and creates a session
- `POST /auth/logout`: Logs out the user by invalidating their session and redirects to the configured URL. You can override the redirect URL by adding a `redirect` query parameter (e.g., `/auth/logout?redirect=/login`)

### Authentication Middleware

```
e.Use(ml.AuthMiddleware())
```

### Getting the User ID

```
userID, authenticated := ml.GetUserID(c)
```

### Logging Out

```
ml.Logout(c)
```

### Cleaning Up Expired Tokens and Sessions

```
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