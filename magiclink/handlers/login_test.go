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
		nil, // bypass patterns
		"http://localhost:8080",
		"/auth/verify",
		"Magic link sent",
		nil,
		false, // disableRateLimiting
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

func TestIsDevBypass_ExactMatch(t *testing.T) {
	exactMap := map[string]bool{"user@example.com": true}

	if !isDevBypass("user@example.com", exactMap, nil) {
		t.Error("expected exact match to return true")
	}
	if isDevBypass("other@example.com", exactMap, nil) {
		t.Error("expected non-match to return false")
	}
}

func TestIsDevBypass_WildcardDomain(t *testing.T) {
	patterns := []string{"*@test.com"}

	if !isDevBypass("anyone@test.com", nil, patterns) {
		t.Error("expected *@test.com to match anyone@test.com")
	}
	if isDevBypass("anyone@other.com", nil, patterns) {
		t.Error("expected *@test.com to not match anyone@other.com")
	}
}

func TestIsDevBypass_WildcardPrefix(t *testing.T) {
	patterns := []string{"loadtest-*@example.com"}

	if !isDevBypass("loadtest-001@example.com", nil, patterns) {
		t.Error("expected pattern to match loadtest-001@example.com")
	}
	if !isDevBypass("loadtest-abc@example.com", nil, patterns) {
		t.Error("expected pattern to match loadtest-abc@example.com")
	}
	if isDevBypass("user@example.com", nil, patterns) {
		t.Error("expected pattern to not match user@example.com")
	}
}

func TestIsDevBypass_MultiplePatterns(t *testing.T) {
	exactMap := map[string]bool{"admin@example.com": true}
	patterns := []string{"*@test.com", "bot-*@example.com"}

	tests := []struct {
		email    string
		expected bool
	}{
		{"admin@example.com", true},   // exact match
		{"user@test.com", true},       // pattern 1
		{"bot-01@example.com", true},  // pattern 2
		{"user@example.com", false},   // no match
	}

	for _, tt := range tests {
		if got := isDevBypass(tt.email, exactMap, patterns); got != tt.expected {
			t.Errorf("isDevBypass(%q) = %v, want %v", tt.email, got, tt.expected)
		}
	}
}

func TestIsDevBypass_EmptyInputs(t *testing.T) {
	if isDevBypass("user@example.com", nil, nil) {
		t.Error("expected false with nil map and nil patterns")
	}
}
