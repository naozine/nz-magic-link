package main

import (
	"html/template"
	"io"
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"

	"github.com/naozine/nz-magic-link/magiclink"
)

// TemplateRenderer Template renderer for Echo
type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
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
		templates: template.Must(template.ParseGlob("examples/simple/templates/*.html")),
	}
	e.Renderer = renderer

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

	config.DatabasePath = "level.db"
	config.DatabaseType = "leveldb"
	config.DatabaseOptions = map[string]string{
		"block_cache_capacity": "33554432", // 32MB
		"write_buffer":         "16777216", // 16MB
	}

	// Create a new MagicLink instance
	ml, err := magiclink.New(config)
	if err != nil {
		e.Logger.Fatal(err)
	}

	// Register the authentication handlers
	ml.RegisterHandlers(e)

	// Public routes
	e.GET("/", func(c echo.Context) error {
		// Check if the user is authenticated
		userID, authenticated := ml.GetUserID(c)
		return c.Render(http.StatusOK, "home.html", map[string]interface{}{
			"authenticated": authenticated,
			"userID":        userID,
		})
	})

	e.GET("/login", func(c echo.Context) error {
		return c.Render(http.StatusOK, "login.html", nil)
	})

	// Protected routes
	protected := e.Group("/dashboard")
	protected.Use(ml.AuthMiddleware())

	protected.GET("", func(c echo.Context) error {
		userID, _ := ml.GetUserID(c)
		return c.Render(http.StatusOK, "dashboard.html", map[string]interface{}{
			"userID": userID,
		})
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
