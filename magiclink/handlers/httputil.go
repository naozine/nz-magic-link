package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"path"
	"strings"
)

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// readJSON decodes the request body as JSON into dst.
func readJSON(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

// realIP extracts the client's real IP address from the request,
// checking X-Forwarded-For and X-Real-IP headers before falling back to RemoteAddr.
func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may contain multiple IPs; the first is the client
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr, stripping the port
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// safeRedirectPath returns the redirect path from the query parameter if it is
// a safe relative path (starts with "/", no scheme or host). Returns fallback otherwise.
func safeRedirectPath(r *http.Request, param string, fallback string) string {
	redirect := r.URL.Query().Get(param)
	if redirect == "" {
		return fallback
	}
	// Must start with "/"
	if !strings.HasPrefix(redirect, "/") {
		return fallback
	}
	// Block protocol-relative URLs ("//evil.com")
	// and backslash variants ("/\evil.com") that some browsers interpret as "//"
	if len(redirect) > 1 && (redirect[1] == '/' || redirect[1] == '\\') {
		return fallback
	}
	// Clean the path to prevent traversal sequences like "/../../"
	cleaned := path.Clean(redirect)
	// path.Clean may strip trailing slash; preserve query string from original
	// but use the cleaned path portion
	if cleaned == "." {
		return fallback
	}
	return cleaned
}
