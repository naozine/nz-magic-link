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

The `SendMagicLinkWithTemplateAndData` method supports a dry run mode that allows you to preview the expanded email template without actually sending the email. This is useful for testing templates, debugging, and development purposes.

When dry run mode is enabled (by setting the `dryRun` parameter to `true`), the method:
- Expands the template with the provided data
- Returns the complete email content as a string (including headers)
- Does **not** send the actual email

```go
// Enable dry run mode to preview the email content
previewContent, err := ml.EmailSender.SendMagicLinkWithTemplateAndData(
    "user@example.com",           // to
    token,                        // token
    30,                          // expiryMinutes
    "Your Order Confirmation",    // subject
    customTemplate,              // template
    customData,                  // data
    true,                        // dryRun - enable preview mode
)
if err != nil {
    log.Printf("Template expansion failed: %v", err)
    return
}

// previewContent now contains the expanded email template
fmt.Println("Email Preview:")
fmt.Println(previewContent)
```

##### Use Cases for Dry Run Mode

- **Template Testing**: Verify that your custom templates expand correctly with real data
- **Development**: Test email functionality without sending actual emails
- **Debugging**: Inspect the final email content to troubleshoot formatting issues
- **Content Validation**: Review email content before sending to ensure accuracy

##### Email Test Example Integration

The [email-test example](examples/email-test) includes a web interface that demonstrates dry run functionality:

- Check the "Preview mode (dry run - don't send email)" checkbox in the form
- The preview content will be displayed in a modal dialog
- This allows you to test different templates and data combinations interactively

#### Error Handling

The method validates that your data structure embeds `BaseTemplateData`. If not, it returns an error:

```go
previewContent, err := ml.EmailSender.SendMagicLinkWithTemplateAndData(to, token, expiry, subject, template, data, dryRun)
if err != nil {
    // Handle validation errors like:
    // "data parameter must embed BaseTemplateData struct"
    log.Printf("Email send failed: %v", err)
}
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