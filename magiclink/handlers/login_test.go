package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/naozine/nz-magic-link/magiclink/internal/email"
	"github.com/naozine/nz-magic-link/magiclink/internal/token"
)

func TestLoginHandler_ConcurrentAccess_RateLimiter(t *testing.T) {
	db := newMockDB()
	tokenMgr := token.New(db, 15*time.Minute)
	emailSender := email.New(email.Config{})

	handler := LoginHandler(
		tokenMgr,
		emailSender,
		100,              // maxAttempts (high to avoid rate limit)
		15*time.Minute,   // window
		map[string]bool{"test@example.com": true}, // bypass emails (skip SMTP)
		"http://localhost:8080",
		"/auth/verify",
		"Magic link sent",
		nil,
	)

	e := echo.New()
	var wg sync.WaitGroup
	const goroutines = 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"email":"test@example.com"}`
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i%256))
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			_ = handler(c)
		}(i)
	}

	wg.Wait()
}
