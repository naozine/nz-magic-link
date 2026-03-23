package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/naozine/nz-magic-link/magiclink/internal/email"
	"github.com/naozine/nz-magic-link/magiclink/internal/emailcheck"
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
		nil,   // emailChecker
	)

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
			handler.ServeHTTP(rec, req)
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

func newTestLoginHandler(checker *emailcheck.Checker) http.HandlerFunc {
	db := newMockDB()
	tokenMgr := token.New(db, 15*time.Minute)
	emailSender := email.New(email.Config{})

	return LoginHandler(
		tokenMgr,
		emailSender,
		100,
		15*time.Minute,
		map[string]bool{"test@example.com": true},
		nil,
		"http://localhost:8080",
		"/auth/verify",
		"Magic link sent",
		nil,
		true, // disableRateLimiting
		checker,
	)
}

func TestLoginHandler_BlacklistedDomain(t *testing.T) {
	var blockedEmail, blockedReason string
	checker := emailcheck.New(emailcheck.Config{
		BlacklistDomains: map[string]bool{"mailinator.com": true},
		OnBlocked: func(email, reason string) {
			blockedEmail = email
			blockedReason = reason
		},
	})

	handler := newTestLoginHandler(checker)
	rec := postJSONRequest(handler, `{"email":"user@mailinator.com"}`)

	// Should return 200 success (not reveal that it was blocked)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp LoginResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Message != "Magic link sent" {
		t.Errorf("unexpected message: %q", resp.Message)
	}

	// OnBlocked should have been called
	if blockedEmail != "user@mailinator.com" {
		t.Errorf("expected blocked email 'user@mailinator.com', got %q", blockedEmail)
	}
	if blockedReason != "disposable email domain" {
		t.Errorf("unexpected reason: %q", blockedReason)
	}
}

func TestLoginHandler_WhitelistedDomain(t *testing.T) {
	checker := emailcheck.New(emailcheck.Config{
		WhitelistDomains: map[string]bool{"example.com": true},
		ValidateMX:       true,
	})

	handler := newTestLoginHandler(checker)
	rec := postJSONRequest(handler, `{"email":"test@example.com"}`)

	// Should return 200 with magic_link (bypass mode)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp LoginResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.MagicLink == "" {
		t.Error("expected magic_link in response (dev bypass)")
	}
}

func TestLoginHandler_NilChecker(t *testing.T) {
	handler := newTestLoginHandler(nil)
	rec := postJSONRequest(handler, `{"email":"test@example.com"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp LoginResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.MagicLink == "" {
		t.Error("expected magic_link in response")
	}
}
