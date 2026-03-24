package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSafeRedirectPath(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		fallback string
		want     string
	}{
		{"relative path", "?redirect=/projects/5", "/default", "/projects/5"},
		{"root path", "?redirect=/", "/default", "/"},
		{"empty param falls back", "", "/default", "/default"},
		{"missing param falls back", "?other=value", "/default", "/default"},
		{"external URL rejected", "?redirect=https://evil.com/steal", "/default", "/default"},
		{"protocol-relative rejected", "?redirect=//evil.com/steal", "/default", "/default"},
		{"no leading slash rejected", "?redirect=evil.com/steal", "/default", "/default"},
		{"javascript scheme rejected", "?redirect=javascript:alert(1)", "/default", "/default"},
		{"empty fallback", "?redirect=notvalid", "", ""},
		{"backslash rejected", "?redirect=/%5Cevil.com", "/default", "/default"},
		{"path traversal cleaned", "?redirect=/a/../b", "/default", "/b"},
		{"deep traversal cleaned", "?redirect=/../../etc/passwd", "/default", "/etc/passwd"},
		{"traversal to root is safe", "?redirect=/a/../../..", "/default", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test"+tt.query, nil)
			got := safeRedirectPath(req, "redirect", tt.fallback)
			if got != tt.want {
				t.Errorf("safeRedirectPath() = %q, want %q", got, tt.want)
			}
		})
	}
}
