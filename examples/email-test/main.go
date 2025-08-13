package main

import (
	"bufio"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"

	"github.com/naozine/nz-magic-link/magiclink"
)

// CustomEmailData embeds BaseTemplateData and adds custom fields.
type CustomEmailData struct {
	magiclink.BaseTemplateData
	UserName string
	OrderID  string
	Amount   float64
}

// TemplateRenderer Template renderer for Echo
type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

// EmailRequest represents the request body for the email sending endpoint
type EmailRequest struct {
	To       string  `json:"to"`
	Subject  string  `json:"subject"`
	Body     string  `json:"body"`
	UserName string  `json:"user_name"`
	OrderID  string  `json:"order_id"`
	Amount   float64 `json:"amount"`
	Preview  bool    `json:"preview"`
}

// EmailResponse represents the response body for the email sending endpoint
type EmailResponse struct {
	Message        string `json:"message"`
	MagicLink      string `json:"magic_link,omitempty"`
	PreviewContent string `json:"preview_content,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error"`
}

func main() {
	// Create a new Echo instance
	e := echo.New()
	e.Logger.SetLevel(log.DEBUG)

	// Configure middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Configure templates
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("examples/email-test/templates/*.html")),
	}
	e.Renderer = renderer

	// Create a default configuration for MagicLink
	config := magiclink.DefaultConfig()

	// Configure SMTP settings
	config.SMTPHost = getEnv("SMTP_HOST", "smtp.example.com")
	config.SMTPPort = 587
	config.SMTPUseTLS = false
	config.SMTPUseSTARTTLS = true
	config.SMTPSkipVerify = false
	config.SMTPUsername = getEnv("SMTP_USERNAME", "your-email@example.com")
	config.SMTPPassword = getEnv("SMTP_PASSWORD", "your-password")
	config.SMTPFrom = getEnv("SMTP_FROM", "your-email@example.com")
	config.SMTPFromName = getEnv("SMTP_FROM_NAME", "Magic Link Email Test")
	config.ServerAddr = getEnv("SERVER_ADDR", "http://localhost:8080")

	// Set the path to the file containing email addresses that should bypass email sending
	config.DevBypassEmailFilePath = getEnv("DEV_BYPASS_EMAIL_FILE", "dev_bypass_emails.txt")

	// Create a new MagicLink instance
	ml, err := magiclink.New(config)
	if err != nil {
		e.Logger.Fatal(err)
	}
	defer ml.Close()

	// Load the dev bypass emails
	devBypassEmails := make(map[string]bool)
	if _, err := os.Stat(config.DevBypassEmailFilePath); err == nil {
		file, err := os.Open(config.DevBypassEmailFilePath)
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				email := strings.TrimSpace(scanner.Text())
				if email != "" && !strings.HasPrefix(email, "#") {
					devBypassEmails[email] = true
				}
			}
		}
	}

	// Routes
	e.GET("/", func(c echo.Context) error {
		return c.Render(http.StatusOK, "email-form.html", nil)
	})

	e.POST("/send-email", func(c echo.Context) error {
		// Parse the request body
		var req EmailRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Invalid request body",
			})
		}

		// Validate the email
		if req.To == "" {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Email address is required",
			})
		}

		// Validate email format
		_, err := mail.ParseAddress(req.To)
		if err != nil {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Invalid email format",
			})
		}

		// Validate the subject
		if req.Subject == "" {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Subject is required",
			})
		}

		// Create a custom email template with the user's body
		customTemplate := fmt.Sprintf(`From: {{.FromName}} <{{.From}}>
To: {{.To}}
Subject: {{.Subject}}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

%s

マジックリンク: {{.MagicLink}}

このリンクは{{.ExpiryMinutes}}分後に期限切れになります。
`, req.Body)

		// Generate a random token (simulating a magic link token)
		token := fmt.Sprintf("test-token-%d", time.Now().Unix())

		// Check if the email is in the bypass list
		if devBypassEmails[req.To] {
			// Construct the magic link
			magicLink := fmt.Sprintf("%s/auth/verify?token=%s", config.ServerAddr, token)

			// Return the magic link in the response
			return c.JSON(http.StatusOK, EmailResponse{
				Message:   "Development mode: Magic link generated",
				MagicLink: magicLink,
			})
		}

		// Generate a token using the token manager
		generatedToken, err := ml.TokenManager.Generate(req.To)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to generate token: " + err.Error(),
			})
		}

		// Create a simple data struct for the custom template
		simpleData := &struct {
			magiclink.BaseTemplateData
		}{}

		// Use SendMagicLinkWithTemplateAndData to send the email with custom template and subject
		previewContent, err := ml.EmailSender.SendMagicLinkWithTemplateAndData(req.To, generatedToken, int(ml.TokenManager.TokenExpiry.Minutes()), req.Subject, customTemplate, simpleData, req.Preview)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to send email: " + err.Error(),
			})
		}

		// Return response based on preview mode
		if req.Preview {
			return c.JSON(http.StatusOK, EmailResponse{
				Message:        "Email preview generated successfully",
				PreviewContent: previewContent,
			})
		} else {
			return c.JSON(http.StatusOK, EmailResponse{
				Message: "Email sent successfully",
			})
		}
	})

	e.POST("/send-custom-email", func(c echo.Context) error {
		// Parse the request body
		var req EmailRequest
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Invalid request body",
			})
		}

		// Validate the email
		if req.To == "" {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Email address is required",
			})
		}

		// Validate email format
		_, err := mail.ParseAddress(req.To)
		if err != nil {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Invalid email format",
			})
		}

		// Validate the subject
		if req.Subject == "" {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Subject is required",
			})
		}

		// Validate custom fields
		if req.UserName == "" {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "User name is required",
			})
		}

		if req.OrderID == "" {
			return c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "Order ID is required",
			})
		}

		// Create a custom email template with custom data macros
		customTemplate := fmt.Sprintf(`From: {{.FromName}} <{{.From}}>
To: {{.To}}
Subject: {{.Subject}}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

%s

カスタムデータ:
- お客様名: {{.UserName}}
- 注文ID: {{.OrderID}}
- 金額: ¥{{.Amount}}

マジックリンク: {{.MagicLink}}

このリンクは{{.ExpiryMinutes}}分後に期限切れになります。
`, req.Body)

		// Generate a random token (simulating a magic link token)
		token := fmt.Sprintf("test-token-%d", time.Now().Unix())

		// Check if the email is in the bypass list
		if devBypassEmails[req.To] {
			// Construct the magic link
			magicLink := fmt.Sprintf("%s/auth/verify?token=%s", config.ServerAddr, token)

			// Return the magic link in the response
			return c.JSON(http.StatusOK, EmailResponse{
				Message:   "Development mode: Custom magic link generated",
				MagicLink: magicLink,
			})
		}

		// Generate a token using the token manager
		generatedToken, err := ml.TokenManager.Generate(req.To)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to generate token: " + err.Error(),
			})
		}

		// Create CustomEmailData instance
		customData := &CustomEmailData{
			UserName: req.UserName,
			OrderID:  req.OrderID,
			Amount:   req.Amount,
		}

		// Use SendMagicLinkWithTemplateAndData to send the email with custom data
		previewContent, err := ml.EmailSender.SendMagicLinkWithTemplateAndData(req.To, generatedToken, int(ml.TokenManager.TokenExpiry.Minutes()), req.Subject, customTemplate, customData, req.Preview)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to send custom email: " + err.Error(),
			})
		}

		// Return response based on preview mode
		if req.Preview {
			return c.JSON(http.StatusOK, EmailResponse{
				Message:        "Custom email preview generated successfully",
				PreviewContent: previewContent,
			})
		} else {
			return c.JSON(http.StatusOK, EmailResponse{
				Message: "Custom email sent successfully",
			})
		}
	})

	// Start the server
	e.Logger.Fatal(e.Start(":8080"))
}

// Helper function to get environment variables with fallback
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
