package emailcheck

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCheck_BlacklistedDomain(t *testing.T) {
	var blocked string
	c := New(Config{
		BlacklistDomains: map[string]bool{"mailinator.com": true},
		OnBlocked:        func(email, reason string) { blocked = reason },
	})

	if !c.Check("user@mailinator.com") {
		t.Error("expected blacklisted domain to be blocked")
	}
	if blocked != "disposable email domain" {
		t.Errorf("unexpected reason: %q", blocked)
	}
}

func TestCheck_WhitelistedDomain(t *testing.T) {
	c := New(Config{
		WhitelistDomains: map[string]bool{"gmail.com": true},
		ValidateMX:       true,
	})
	// Should not be blocked, and MX lookup should be skipped
	c.lookupMX = func(domain string) ([]*net.MX, error) {
		t.Error("MX lookup should not be called for whitelisted domain")
		return nil, nil
	}

	if c.Check("user@gmail.com") {
		t.Error("expected whitelisted domain to not be blocked")
	}
}

func TestCheck_NoValidation(t *testing.T) {
	c := New(Config{})

	if c.Check("user@unknown-domain.com") {
		t.Error("expected no block when no validation is configured")
	}
}

func TestCheck_MX_Valid(t *testing.T) {
	c := New(Config{ValidateMX: true})
	c.lookupMX = func(domain string) ([]*net.MX, error) {
		return []*net.MX{{Host: "mx.example.com", Pref: 10}}, nil
	}

	if c.Check("user@example.com") {
		t.Error("expected valid MX domain to not be blocked")
	}

	// Second call should use cache, not lookup
	c.lookupMX = func(domain string) ([]*net.MX, error) {
		t.Error("MX lookup should not be called for cached domain")
		return nil, nil
	}

	if c.Check("user@example.com") {
		t.Error("expected cached domain to not be blocked")
	}
}

func TestCheck_MX_Invalid(t *testing.T) {
	var blocked string
	c := New(Config{
		ValidateMX: true,
		OnBlocked:  func(email, reason string) { blocked = reason },
	})
	c.lookupMX = func(domain string) ([]*net.MX, error) {
		return nil, &net.DNSError{Err: "no such host"}
	}

	if !c.Check("user@nonexistent.invalid") {
		t.Error("expected domain with no MX to be blocked")
	}
	if blocked != "no MX records for domain" {
		t.Errorf("unexpected reason: %q", blocked)
	}
}

func TestCheck_MX_EmptyRecords(t *testing.T) {
	c := New(Config{ValidateMX: true})
	c.lookupMX = func(domain string) ([]*net.MX, error) {
		return []*net.MX{}, nil
	}

	if !c.Check("user@empty-mx.com") {
		t.Error("expected domain with empty MX records to be blocked")
	}
}

func TestCheck_CaseInsensitive(t *testing.T) {
	c := New(Config{
		BlacklistDomains: map[string]bool{"mailinator.com": true},
		WhitelistDomains: map[string]bool{"gmail.com": true},
	})

	if !c.Check("user@MAILINATOR.COM") {
		t.Error("expected case-insensitive blacklist match")
	}
	if c.Check("user@Gmail.COM") {
		t.Error("expected case-insensitive whitelist match")
	}
}

func TestCheck_OnBlockedNil(t *testing.T) {
	c := New(Config{
		BlacklistDomains: map[string]bool{"mailinator.com": true},
		OnBlocked:        nil,
	})

	// Should not panic
	if !c.Check("user@mailinator.com") {
		t.Error("expected blocked")
	}
}

func TestCheck_InvalidEmail(t *testing.T) {
	c := New(Config{BlacklistDomains: map[string]bool{"test.com": true}})

	if c.Check("no-at-sign") {
		t.Error("expected invalid email to not be blocked")
	}
}

func TestCheck_ConcurrentAccess(t *testing.T) {
	c := New(Config{
		ValidateMX:       true,
		WhitelistDomains: map[string]bool{"gmail.com": true},
		BlacklistDomains: map[string]bool{"mailinator.com": true},
	})
	c.lookupMX = func(domain string) ([]*net.MX, error) {
		return []*net.MX{{Host: "mx.example.com"}}, nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				c.Check("user@gmail.com")
			case 1:
				c.Check("user@mailinator.com")
			case 2:
				c.Check("user@unknown.com")
			}
		}(i)
	}
	wg.Wait()
}

func TestLoadDomainFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")

	content := `# This is a comment
gmail.com
Yahoo.CO.JP

  hotmail.com
# another comment
`
	os.WriteFile(path, []byte(content), 0644)

	domains, err := LoadDomainFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(domains) != 3 {
		t.Fatalf("expected 3 domains, got %d", len(domains))
	}
	if !domains["gmail.com"] {
		t.Error("expected gmail.com")
	}
	if !domains["yahoo.co.jp"] {
		t.Error("expected yahoo.co.jp (lowercased)")
	}
	if !domains["hotmail.com"] {
		t.Error("expected hotmail.com (trimmed)")
	}
}

func TestLoadDomainFile_NotFound(t *testing.T) {
	_, err := LoadDomainFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
