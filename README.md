# Magic Link Authentication for Go/Echo

A simple, secure passwordless authentication library for Go applications using the Echo web framework. This library provides magic link authentication via email and optional WebAuthn/Passkey support, allowing users to sign in without passwords.

## Features

- **Passwordless Authentication**: Send magic links via email for secure, passwordless login
- **WebAuthn/Passkey Support**: Optional passkey authentication (fingerprint, face recognition, etc.)
- **Multiple Storage Backends**: SQLite (pure Go, no CGo) and LevelDB
- **In-Memory Token Storage**: Optional high-performance mode for high-concurrency scenarios
- **Secure by Default**: Implements security best practices for tokens and sessions
- **Rate Limiting**: Prevents abuse with configurable rate limits
- **Customizable**: Flexible configuration for tokens, sessions, and emails
- **Echo Integration**: Easy to integrate with Echo web applications

## Installation

```bash
go get github.com/naozine/nz-magic-link
```

## Quick Start

For complete working examples, please refer to the following directories in the repository:

### Simple Example ([examples/simple](examples/simple))

This example demonstrates:

- Setting up an Echo server with the magic link authentication system
- Configuring SMTP settings for sending emails
- Creating public and protected routes
- Using HTML templates for login and dashboard pages
- Handling environment variables for configuration

### Email Testing Example ([examples/email-test](examples/email-test))

This example provides a form-based interface for testing email sending functionality:

- Form with fields for To, Subject, and message body
- Custom email template generation based on user input
- Token generation and magic link creation
- Development mode for bypassing actual email sending

### WebAuthn Example ([examples/webauthn-simple](examples/webauthn-simple))

This example demonstrates passkey/WebAuthn authentication:

- Passkey registration and login flows
- Discoverable credential support
- Combined magic link + passkey authentication

Here's a brief overview of how to use the library:

1. Create a new Echo instance
2. Configure the MagicLink instance with your SMTP settings
3. Register the authentication handlers
4. Create protected routes using the authentication middleware
5. Start the server

The example in the repository provides a more comprehensive implementation that you can use as a starting point for your own application.

## Configuration

The library can be configured using the `Config` struct:

```go
config := magiclink.DefaultConfig()
```

### Database Configuration

- `DatabasePath`: Path to the database file (default: `"magiclink.db"`)
- `DatabaseType`: Storage backend — `"sqlite"` or `"leveldb"` (default: `"sqlite"`)
- `DatabaseOptions`: Backend-specific options as `map[string]string` (default: `{}`)
  - SQLite options: `journal_mode`, `synchronous`, `cache_size`, `temp_store`
  - LevelDB options: `block_cache_capacity`, `write_buffer`, `compaction_table_size`

### Email Configuration

- `SMTPHost`: SMTP server hostname
- `SMTPPort`: SMTP server port (default: `587`)
- `SMTPUsername`: SMTP username for authentication
- `SMTPPassword`: SMTP password for authentication
- `SMTPFrom`: Email address to send from
- `SMTPFromName`: Name to display in the From field
- `SMTPUseTLS`: Use TLS from the start — implicit TLS on port 465 (default: `false`)
- `SMTPUseSTARTTLS`: Use STARTTLS — upgrade to TLS on port 587 (default: `true`)
- `SMTPSkipVerify`: Skip TLS certificate verification (default: `false`)
- `EmailTemplate`: Custom email template (optional)
- `EmailSubject`: Email subject line (default: `"Your Magic Link for Authentication"`)
- `ServerAddr`: Server address for constructing magic links (default: `"http://localhost:8080"`)

### Token Configuration

- `TokenExpiry`: How long tokens are valid for (default: `30 * time.Minute`)
- `UseInMemoryTokens`: Store tokens in memory instead of the database for high-concurrency scenarios (default: `true`). Sessions still use the database. See [In-Memory Token Storage](#in-memory-token-storage) for details.

### Session Configuration

- `SessionExpiry`: How long sessions are valid for (default: `7 * 24 * time.Hour`)
- `CookieName`: Name of the session cookie (default: `"session"`)
- `CookieSecure`: Whether to set the Secure flag on cookies (default: `true`)
- `CookieHTTPOnly`: Whether to set the HttpOnly flag on cookies (default: `true`)
- `CookieSameSite`: SameSite policy for cookies (default: `"lax"`)
- `CookieDomain`: Domain for cookies (optional)
- `CookiePath`: Path for cookies (default: `"/"`)

### URL Configuration

- `LoginURL`: URL for the login endpoint (default: `"/auth/login"`)
- `VerifyURL`: URL for the verification endpoint (default: `"/auth/verify"`)
- `RedirectURL`: URL to redirect to after successful verification (default: `"/"`)
- `LogoutRedirectURL`: URL to redirect to after successful logout (default: `"/"`)
- `ErrorRedirectURL`: URL to redirect to on verification error (optional)

### Rate Limiting

- `MaxLoginAttempts`: Maximum number of login attempts per email within the window (default: `5`)
- `RateLimitWindow`: Time window for rate limiting (default: `15 * time.Minute`)
- `DisableRateLimiting`: Disable all rate limiting — both IP-based and per-email (default: `false`). Useful for testing and benchmarking.

### Login Customization

- `LoginSuccessMessage`: Message returned after a successful login request (default: `"Magic link sent to your email"`)
- `AllowLogin`: Callback function `func(c echo.Context, email string) error` to control who can log in. Return an error to reject the login.

### Development Configuration

- `DevBypassEmailFilePath`: Path to a file containing email addresses that should bypass email sending. This is useful for development and testing purposes. The file should contain one email address per line. If an email address in this file requests a magic link, the link will be returned in the response instead of being sent via email, allowing for easier testing of the authentication flow.

### WebAuthn/Passkey Configuration

- `WebAuthnEnabled`: Enable WebAuthn/Passkey support (default: `false`)
- `WebAuthnRPID`: Relying Party ID, typically the domain (default: `"localhost"`)
- `WebAuthnRPName`: Relying Party display name (default: `"nz-magic-link"`)
- `WebAuthnAllowedOrigins`: Allowed origins for WebAuthn (default: `["http://localhost:8080"]`)
- `WebAuthnChallengeTTL`: Challenge expiry time (default: `5 * time.Minute`)
- `WebAuthnTimeout`: Client-side timeout (default: `60 * time.Second`)
- `WebAuthnUserVerification`: User verification requirement — `"preferred"`, `"required"`, or `"discouraged"` (default: `"preferred"`)
- `WebAuthnRequireResidentKey`: Require discoverable credentials (default: `true`)
- `WebAuthnRedirectURL`: Redirect URL after successful WebAuthn login (default: `"/dashboard"`)

## API Reference

### Creating a New Instance

```go
ml, err := magiclink.New(config)
```

To use an existing `*sql.DB` connection (SQLite only):

```go
ml, err := magiclink.NewWithDB(config, db)
```

### Registering Handlers

```go
ml.RegisterHandlers(e)
```

This registers the following endpoints:

**Magic Link:**
- `POST /auth/login`: Accepts an email address and sends a magic link. If the email is in the bypass list (specified by `DevBypassEmailFilePath`), the magic link will be returned in the response as `magic_link` instead of being sent via email.
- `GET /auth/verify`: Verifies a token from a magic link and creates a session
- `POST /auth/logout`: Logs out the user by invalidating their session. You can override the redirect URL with a `redirect` query parameter.

**WebAuthn (when enabled):**
- `POST /webauthn/register/start`: Initiates passkey registration
- `POST /webauthn/register/finish`: Completes passkey registration
- `POST /webauthn/login/start`: Initiates passkey authentication
- `POST /webauthn/login/finish`: Completes passkey authentication
- `POST /webauthn/login/discoverable`: Initiates discoverable (userless) authentication
- `GET /webauthn/static/webauthn.js`: Serves the WebAuthn client script

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

### Closing

```go
ml.Close()
```

### Custom Email Templates with Data

The library provides advanced email functionality through the `SendMagicLinkWithTemplateAndData` method, which allows you to send emails with custom templates and additional data fields.

#### Basic Usage

```go
// Define custom data structure that embeds BaseTemplateData
type CustomEmailData struct {
    magiclink.BaseTemplateData
    UserName string
    OrderID  string
    Amount   float64
}

// Create custom template with additional macros
customTemplate := `From: {{.FromName}} <{{.From}}>
To: {{.To}}
Subject: {{.Subject}}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Hello {{.UserName}},

Your order {{.OrderID}} for ¥{{.Amount}} has been processed.

Click the link below to authenticate:
{{.MagicLink}}

This link will expire in {{.ExpiryMinutes}} minutes.

Best regards,
{{.FromName}}`

// Create custom data instance
customData := &CustomEmailData{
    UserName: "John Doe",
    OrderID:  "ORDER-12345",
    Amount:   9800.00,
}

// Send email with custom template and data
_, err := ml.EmailSender.SendMagicLinkWithTemplateAndData(
    "user@example.com",           // to
    token,                        // token
    30,                          // expiryMinutes
    "Your Order Confirmation",    // subject
    customTemplate,              // template
    customData,                  // data
    false,                       // dryRun
)
```

#### Required Structure

Your custom data struct **must** embed `magiclink.BaseTemplateData` to ensure compatibility with the standard template macros:

```go
type YourCustomData struct {
    magiclink.BaseTemplateData  // Required embedding
    // Your custom fields
    CustomField1 string
    CustomField2 int
}
```

#### Standard Template Macros

The following macros are automatically populated in the `BaseTemplateData`:

- `{{.From}}` - Sender email address
- `{{.FromName}}` - Sender name (encoded for email headers)
- `{{.FromNameOriginal}}` - Original sender name (unencoded)
- `{{.To}}` - Recipient email address
- `{{.Subject}}` - Email subject (encoded for email headers)
- `{{.MagicLink}}` - Generated magic link URL
- `{{.ExpiryMinutes}}` - Token expiry time in minutes

#### Dry Run Mode

Set `dryRun` to `true` to preview the expanded email template without sending:

```go
previewContent, err := ml.EmailSender.SendMagicLinkWithTemplateAndData(
    "user@example.com", token, 30, "Subject", customTemplate, customData, true,
)
// previewContent contains the expanded email template
```

## In-Memory Token Storage

For high-concurrency scenarios (e.g., ticket lottery announcements where thousands of users log in simultaneously), SQLite's serialized writes can become a bottleneck. Enable in-memory token storage to eliminate DB writes during the login phase:

```go
config := magiclink.DefaultConfig()
config.UseInMemoryTokens = true
```

**How it works:**
- Login phase (send magic link): Token is saved in memory — zero DB writes
- Verify phase (click magic link): Token is read from memory, session is saved to DB — one DB write
- Sessions, passkeys, and other data still use the configured database

**Trade-off:** If the process restarts, pending (unverified) tokens are lost. Users simply re-click the login button. This is acceptable because tokens are short-lived (30 minutes by default) and disposable.

## Security Considerations

- Tokens are cryptographically secure (256-bit) and hashed (SHA-256) before storage
- Sessions use secure cookies with HttpOnly and SameSite flags
- Session IDs are hashed before storage
- Rate limiting prevents brute force attacks
- Tokens are single-use and expire automatically
- Token verification and session creation are atomic (single transaction)

## License

MIT
