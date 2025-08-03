// Package email provides functionality for sending emails with magic links.
package email

import (
	"bytes"
	"fmt"
	"net/smtp"
	"text/template"
)

// Config holds the configuration for sending emails.
type Config struct {
	Host       string
	Port       int
	Username   string
	Password   string
	From       string
	FromName   string
	Template   string
	VerifyURL  string
	ServerAddr string
}

// DefaultTemplate is the default email template for magic links.
const DefaultTemplate = `From: {{.FromName}} <{{.From}}>
To: {{.To}}
Subject: Your Magic Link for Authentication

Hello,

You requested a magic link to sign in. Click the link below to authenticate:

{{.MagicLink}}

This link will expire in {{.ExpiryMinutes}} minutes.

If you didn't request this link, you can safely ignore this email.

Best regards,
{{.FromName}}
`

// Sender handles sending emails with magic links.
type Sender struct {
	Config Config
}

// New creates a new email sender.
func New(config Config) *Sender {
	// If no template is provided, use the default
	if config.Template == "" {
		config.Template = DefaultTemplate
	}

	return &Sender{
		Config: config,
	}
}

// SendMagicLink sends a magic link to the specified email address.
func (s *Sender) SendMagicLink(to, token string, expiryMinutes int) error {
	// Prepare the magic link
	magicLink := fmt.Sprintf("%s%s?token=%s", s.Config.ServerAddr, s.Config.VerifyURL, token)

	// Prepare the email data
	data := struct {
		From          string
		FromName      string
		To            string
		MagicLink     string
		ExpiryMinutes int
	}{
		From:          s.Config.From,
		FromName:      s.Config.FromName,
		To:            to,
		MagicLink:     magicLink,
		ExpiryMinutes: expiryMinutes,
	}

	// Parse the template
	tmpl, err := template.New("email").Parse(s.Config.Template)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	// Execute the template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	// Set up authentication
	auth := smtp.PlainAuth("", s.Config.Username, s.Config.Password, s.Config.Host)

	// Send the email
	addr := fmt.Sprintf("%s:%d", s.Config.Host, s.Config.Port)
	err = smtp.SendMail(addr, auth, s.Config.From, []string{to}, body.Bytes())
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}