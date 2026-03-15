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
	e := echo.New()

	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	config := magiclink.DefaultConfig()
	config.DatabasePath = "magiclink.db"
	config.DatabaseType = "sqlite"
	config.ServerAddr = "http://localhost:8080"

	// Email bypass for development
	config.DevBypassEmailFilePath = ".bypass_emails"

	// WebAuthn Configuration
	config.WebAuthnEnabled = true
	config.WebAuthnRPID = "localhost"
	config.WebAuthnRPName = "WebAuthn Example"
	config.WebAuthnAllowedOrigins = []string{"http://localhost:8080"}
	config.WebAuthnRedirectURL = "/dashboard"

	ml, err := magiclink.New(config)
	if err != nil {
		log.Fatalf("Failed to create MagicLink instance: %v", err)
	}
	defer ml.Close()

	ml.RegisterHandlers(e)

	t := &Template{
		templates: template.Must(template.ParseGlob("examples/webauthn-simple/views/*.html")),
	}
	e.Renderer = t

	// Home / Login page
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
		return c.Render(http.StatusOK, "dashboard.html", map[string]interface{}{
			"UserID": userID,
		})
	}, ml.AuthMiddleware())

	// Create bypass file if not exists
	if _, err := os.Stat(".bypass_emails"); os.IsNotExist(err) {
		os.WriteFile(".bypass_emails", []byte("test@example.com\n"), 0644)
	}

	log.Println("Server started at http://localhost:8080")
	log.Fatal(e.Start(":8080"))
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}
