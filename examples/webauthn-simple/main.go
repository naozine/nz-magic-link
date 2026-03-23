package main

import (
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/naozine/nz-magic-link/magiclink"
)

var templates = template.Must(template.ParseGlob("examples/webauthn-simple/views/*.html"))

func main() {
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

	mux := http.NewServeMux()

	// Register the authentication handlers
	mux.Handle("/auth/", ml.Handler())
	mux.Handle("/webauthn/", ml.Handler())

	// Home / Login page
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		userID, authenticated := ml.GetUserID(r)
		templates.ExecuteTemplate(w, "index.html", map[string]interface{}{
			"Authenticated": authenticated,
			"UserID":        userID,
		})
	})

	// Protected route
	mux.Handle("GET /dashboard", ml.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, _ := ml.GetUserID(r)
		templates.ExecuteTemplate(w, "dashboard.html", map[string]interface{}{
			"UserID": userID,
		})
	})))

	// Create bypass file if not exists
	if _, err := os.Stat(".bypass_emails"); os.IsNotExist(err) {
		os.WriteFile(".bypass_emails", []byte("test@example.com\n"), 0644)
	}

	log.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
