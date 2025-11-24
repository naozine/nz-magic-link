package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/naozine/nz-magic-link/magiclink"
)

func main() {
	// Create a new Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Configure MagicLink with WebAuthn enabled
	config := magiclink.DefaultConfig()
	config.DatabasePath = "magiclink.db"
	config.ServerAddr = "http://localhost:8080"

	// SMTP settings (Required for email-based registration flow if used, but we focus on WebAuthn here)
	// For this example, we'll use bypass file for email flow or just assume user already exists/registers via WebAuthn
	config.DevBypassEmailFilePath = ".bypass_emails"

	// WebAuthn Configuration
	config.WebAuthnEnabled = true
	config.WebAuthnRPID = "localhost"
	config.WebAuthnRPName = "WebAuthn Example"
	config.WebAuthnAllowedOrigins = []string{"http://localhost:8080"}
	config.LoginURL = "/auth/login"
	config.VerifyURL = "/auth/verify"
	config.DatabaseType = "leveldb"

	// Create MagicLink instance
	ml, err := magiclink.New(config)
	if err != nil {
		log.Fatalf("Failed to create MagicLink instance: %v", err)
	}
	defer ml.Close()

	// Register MagicLink handlers
	ml.RegisterHandlers(e)

	// Setup templates
	t := &Template{
		templates: template.Must(template.ParseGlob("views/*.html")),
	}
	e.Renderer = t

	// Routes
	e.GET("/", func(c echo.Context) error {
		userID, authenticated := ml.GetUserID(c)
		return c.Render(http.StatusOK, "index.html", map[string]interface{}{
			"Authenticated": authenticated,
			"UserID":        userID,
		})
	})

	// Protected route
	e.GET("/dashboard", func(c echo.Context) error {
		userID, _ := ml.GetUserID(c)
		return c.HTML(http.StatusOK, "<h1>Dashboard</h1><p>Welcome, "+userID+"!</p><a href='/'>Back to Home</a>")
	}, ml.AuthMiddleware())

	// Create bypass file if not exists
	if _, err := os.Stat(".bypass_emails"); os.IsNotExist(err) {
		os.WriteFile(".bypass_emails", []byte("test@example.com\n"), 0644)
	}

	// Start server
	log.Println("Server started at http://localhost:8080")
	log.Fatal(e.Start(":8080"))
}

// Template renderer
type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}
