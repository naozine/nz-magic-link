package main

import (
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/naozine/nz-magic-link/magiclink"
)

var templates = template.Must(template.ParseGlob("examples/simple/templates/*.html"))

func main() {
	// Create a default configuration for MagicLink
	config := magiclink.DefaultConfig()

	// Configure SMTP settings for port 465 (SSL/TLS)
	config.SMTPHost = getEnv("SMTP_HOST", "smtp.example.com")
	config.SMTPPort = 587         // Use port 465 for SSL/TLS
	config.SMTPUseTLS = false     // Enable TLS from start for port 465
	config.SMTPUseSTARTTLS = true // Disable STARTTLS when using port 465
	config.SMTPSkipVerify = false // Set to true for self-signed certificates
	config.SMTPUsername = getEnv("SMTP_USERNAME", "your-email@example.com")
	config.SMTPPassword = getEnv("SMTP_PASSWORD", "your-password")
	config.SMTPFrom = getEnv("SMTP_FROM", "your-email@example.com")
	config.SMTPFromName = getEnv("SMTP_FROM_NAME", "Magic Link Example")
	config.ServerAddr = getEnv("SERVER_ADDR", "http://localhost:8080")
	// Configure error redirect for verify failures to render a friendly page in this example app
	config.ErrorRedirectURL = "/error"

	// Set the path to the file containing email addresses that should bypass email sending
	config.DevBypassEmailFilePath = getEnv("DEV_BYPASS_EMAIL_FILE", "dev_bypass_emails.txt")

	// Set Japanese email subject and template
	config.EmailSubject = "認証用マジックリンク"
	config.EmailTemplate = `From: {{.FromName}} <{{.From}}>
To: {{.To}}
Subject: {{.Subject}}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

こんにちは、

サインインのためのマジックリンクをリクエストしました。以下のリンクをクリックして認証してください：

{{.MagicLink}}

このリンクは{{.ExpiryMinutes}}分後に期限切れになります。

このリンクをリクエストしていない場合は、このメールを無視してください。

よろしくお願いいたします。
{{.FromNameOriginal}}
`

	config.DatabasePath = "magiclink.db"
	config.DatabaseType = "sqlite"

	// Create a new MagicLink instance
	ml, err := magiclink.New(config)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// Register the authentication handlers
	mux.Handle("/auth/", ml.Handler())

	// Error page route for verify failures
	mux.HandleFunc("GET /error", func(w http.ResponseWriter, r *http.Request) {
		errorCode := r.URL.Query().Get("error")
		description := r.URL.Query().Get("error_description")
		statusCode := r.URL.Query().Get("code")
		templates.ExecuteTemplate(w, "error.html", map[string]interface{}{
			"error":             errorCode,
			"error_description": description,
			"code":              statusCode,
		})
	})

	// Public routes
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		userID, authenticated := ml.ValidateSession(r)
		templates.ExecuteTemplate(w, "home.html", map[string]interface{}{
			"authenticated": authenticated,
			"userID":        userID,
		})
	})

	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		templates.ExecuteTemplate(w, "login.html", nil)
	})

	// Protected routes
	mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
		userID, authenticated := ml.ValidateSession(r)
		if !authenticated {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		templates.ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
			"userID": userID,
		})
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
