// Package emailcheck provides email domain quality validation.
package emailcheck

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// Config holds the configuration for email domain checking.
type Config struct {
	WhitelistDomains map[string]bool
	BlacklistDomains map[string]bool
	ValidateMX       bool
	OnBlocked        func(email string, reason string)
}

// Checker performs email domain quality checks.
type Checker struct {
	config       Config
	mxValidCache sync.Map
	lookupMX     func(domain string) ([]*net.MX, error)
}

// New creates a new Checker.
func New(config Config) *Checker {
	return &Checker{
		config:   config,
		lookupMX: net.LookupMX,
	}
}

// Check returns true if the email should be blocked.
func (c *Checker) Check(email string) bool {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])

	// Blacklist check
	if c.config.BlacklistDomains != nil && c.config.BlacklistDomains[domain] {
		c.notifyBlocked(email, "disposable email domain")
		return true
	}

	// Whitelist check
	if c.config.WhitelistDomains != nil && c.config.WhitelistDomains[domain] {
		return false
	}

	// MX record validation
	if !c.config.ValidateMX {
		return false
	}

	// Check MX cache
	if _, ok := c.mxValidCache.Load(domain); ok {
		return false
	}

	// DNS lookup
	records, err := c.lookupMX(domain)
	if err != nil || len(records) == 0 {
		c.notifyBlocked(email, "no MX records for domain")
		return true
	}

	// Cache the validated domain
	c.mxValidCache.Store(domain, true)
	return false
}

func (c *Checker) notifyBlocked(email, reason string) {
	if c.config.OnBlocked != nil {
		c.config.OnBlocked(email, reason)
	}
}

// LoadDomainFile reads a file with one domain per line.
// Lines starting with # are comments, empty lines are skipped.
// All domains are normalized to lowercase.
func LoadDomainFile(filePath string) (map[string]bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open domain file: %w", err)
	}
	defer file.Close()

	domains := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains[strings.ToLower(line)] = true
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading domain file: %w", err)
	}

	return domains, nil
}
