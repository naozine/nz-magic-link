package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/naozine/nz-magic-link/magiclink"
)

// CustomEmailData embeds BaseTemplateData and adds custom fields.
type CustomEmailData struct {
	magiclink.BaseTemplateData
	UserName string
	OrderID  string
	Amount   float64
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

var templates = template.Must(template.ParseGlob("examples/email-test/templates/*.html"))

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func main() {
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
		log.Fatal(err)
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

	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		templates.ExecuteTemplate(w, "email-form.html", nil)
	})

	mux.HandleFunc("POST /send-email", func(w http.ResponseWriter, r *http.Request) {
		// Parse the request body
		var req EmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Invalid request body",
			})
			return
		}

		// Validate the email
		if req.To == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Email address is required",
			})
			return
		}

		// Validate email format
		_, err := mail.ParseAddress(req.To)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Invalid email format",
			})
			return
		}

		// Validate the subject
		if req.Subject == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Subject is required",
			})
			return
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
			writeJSON(w, http.StatusOK, EmailResponse{
				Message:   "Development mode: Magic link generated",
				MagicLink: magicLink,
			})
			return
		}

		// Generate a token using the token manager
		generatedToken, err := ml.TokenManager.Generate(req.To)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to generate token: " + err.Error(),
			})
			return
		}

		// Create a simple data struct for the custom template
		simpleData := &struct {
			magiclink.BaseTemplateData
		}{}

		// Use SendMagicLinkWithTemplateAndData to send the email with custom template and subject
		previewContent, err := ml.EmailSender.SendMagicLinkWithTemplateAndData(req.To, generatedToken, int(ml.TokenManager.TokenExpiry.Minutes()), req.Subject, customTemplate, simpleData, req.Preview)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to send email: " + err.Error(),
			})
			return
		}

		// Return response based on preview mode
		if req.Preview {
			writeJSON(w, http.StatusOK, EmailResponse{
				Message:        "Email preview generated successfully",
				PreviewContent: previewContent,
			})
		} else {
			writeJSON(w, http.StatusOK, EmailResponse{
				Message: "Email sent successfully",
			})
		}
	})

	mux.HandleFunc("POST /send-custom-email", func(w http.ResponseWriter, r *http.Request) {
		// Parse the request body
		var req EmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Invalid request body",
			})
			return
		}

		// Validate the email
		if req.To == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Email address is required",
			})
			return
		}

		// Validate email format
		_, err := mail.ParseAddress(req.To)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Invalid email format",
			})
			return
		}

		// Validate the subject
		if req.Subject == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Subject is required",
			})
			return
		}

		// Validate custom fields
		if req.UserName == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "User name is required",
			})
			return
		}

		if req.OrderID == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Order ID is required",
			})
			return
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
			writeJSON(w, http.StatusOK, EmailResponse{
				Message:   "Development mode: Custom magic link generated",
				MagicLink: magicLink,
			})
			return
		}

		// Generate a token using the token manager
		generatedToken, err := ml.TokenManager.Generate(req.To)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to generate token: " + err.Error(),
			})
			return
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
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: "Failed to send custom email: " + err.Error(),
			})
			return
		}

		// Return response based on preview mode
		if req.Preview {
			writeJSON(w, http.StatusOK, EmailResponse{
				Message:        "Custom email preview generated successfully",
				PreviewContent: previewContent,
			})
		} else {
			writeJSON(w, http.StatusOK, EmailResponse{
				Message: "Custom email sent successfully",
			})
		}
	})

	// Start the server
	log.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

// Helper function to get environment variables with fallback
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
