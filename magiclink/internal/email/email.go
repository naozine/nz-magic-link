// Package email provides functionality for sending emails with magic links.
package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"mime"
	"net/smtp"
	"reflect"
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
	Subject    string
	VerifyURL  string
	ServerAddr string
	// TLS configuration
	UseTLS        bool // Use TLS from the start (port 465)
	UseSTARTTLS   bool // Use STARTTLS (port 587)
	SkipTLSVerify bool // Skip TLS certificate verification
}

// BaseTemplateData contains the standard fields for email templates.
// This struct should be embedded in custom data structures to ensure
// compatibility with existing template macros.
type BaseTemplateData struct {
	From             string
	FromName         string
	FromNameOriginal string
	To               string
	Subject          string
	MagicLink        string
	ExpiryMinutes    int
}

// DefaultTemplate is the default email template for magic links.
const DefaultTemplate = `From: {{.FromName}} <{{.From}}>
To: {{.To}}
Subject: {{.Subject}}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

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
	// Use subject from config or default if not set
	subject := s.Config.Subject
	if subject == "" {
		subject = "Your Magic Link for Authentication"
	}
	return s.SendMagicLinkWithSubject(to, token, expiryMinutes, subject)
}

// SendMagicLinkWithSubject sends a magic link to the specified email address with a custom subject.
func (s *Sender) SendMagicLinkWithSubject(to, token string, expiryMinutes int, subject string) error {
	return s.SendMagicLinkWithTemplate(to, token, expiryMinutes, subject, s.Config.Template)
}

// SendMagicLinkWithTemplate sends a magic link to the specified email address with custom subject and template.
func (s *Sender) SendMagicLinkWithTemplate(to, token string, expiryMinutes int, subject string, templateStr string) error {
	// Prepare the magic link
	magicLink := fmt.Sprintf("%s%s?token=%s", s.Config.ServerAddr, s.Config.VerifyURL, token)

	// Encode the FromName for email headers if it contains non-ASCII characters
	encodedFromName := s.Config.FromName
	if s.Config.FromName != mime.BEncoding.Encode("UTF-8", s.Config.FromName) {
		// Only encode if it contains non-ASCII characters
		encodedFromName = mime.BEncoding.Encode("UTF-8", s.Config.FromName)
	}

	// Encode the Subject for email headers if it contains non-ASCII characters
	encodedSubject := subject
	if subject != mime.BEncoding.Encode("UTF-8", subject) {
		// Only encode if it contains non-ASCII characters
		encodedSubject = mime.BEncoding.Encode("UTF-8", subject)
	}

	// Prepare the email data
	data := struct {
		From             string
		FromName         string
		FromNameOriginal string
		To               string
		Subject          string
		MagicLink        string
		ExpiryMinutes    int
	}{
		From:             s.Config.From,
		FromName:         encodedFromName,
		FromNameOriginal: s.Config.FromName,
		To:               to,
		Subject:          encodedSubject,
		MagicLink:        magicLink,
		ExpiryMinutes:    expiryMinutes,
	}

	// Parse the template using the provided template parameter
	tmpl, err := template.New("email").Parse(templateStr)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	// Execute the template
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	// Send the email based on configuration
	if s.Config.UseTLS {
		return s.sendWithTLS(to, body.Bytes())
	} else {
		return s.sendWithSTARTTLS(to, body.Bytes())
	}
}

// SendMagicLinkWithTemplateAndData sends a magic link with custom template and data.
// The data parameter must be a struct that embeds BaseTemplateData.
func (s *Sender) SendMagicLinkWithTemplateAndData(to, token string, expiryMinutes int, subject, templateStr string, data interface{}) error {
	// Validate that data contains BaseTemplateData using reflection
	dataValue := reflect.ValueOf(data)
	if dataValue.Kind() == reflect.Ptr {
		dataValue = dataValue.Elem()
	}

	if dataValue.Kind() != reflect.Struct {
		return fmt.Errorf("data parameter must be a struct")
	}

	dataType := dataValue.Type()
	baseTemplateField, found := dataType.FieldByName("BaseTemplateData")
	if !found || baseTemplateField.Type != reflect.TypeOf(BaseTemplateData{}) {
		return fmt.Errorf("data parameter must embed BaseTemplateData struct")
	}

	// Prepare the magic link
	magicLink := fmt.Sprintf("%s%s?token=%s", s.Config.ServerAddr, s.Config.VerifyURL, token)

	// Encode the FromName for email headers if it contains non-ASCII characters
	encodedFromName := s.Config.FromName
	if s.Config.FromName != mime.BEncoding.Encode("UTF-8", s.Config.FromName) {
		// Only encode if it contains non-ASCII characters
		encodedFromName = mime.BEncoding.Encode("UTF-8", s.Config.FromName)
	}

	// Encode the Subject for email headers if it contains non-ASCII characters
	encodedSubject := subject
	if subject != mime.BEncoding.Encode("UTF-8", subject) {
		// Only encode if it contains non-ASCII characters
		encodedSubject = mime.BEncoding.Encode("UTF-8", subject)
	}

	// Set the BaseTemplateData fields in the provided data
	baseTemplateValue := dataValue.FieldByName("BaseTemplateData")
	if baseTemplateValue.CanSet() {
		baseTemplate := BaseTemplateData{
			From:             s.Config.From,
			FromName:         encodedFromName,
			FromNameOriginal: s.Config.FromName,
			To:               to,
			Subject:          encodedSubject,
			MagicLink:        magicLink,
			ExpiryMinutes:    expiryMinutes,
		}
		baseTemplateValue.Set(reflect.ValueOf(baseTemplate))
	}

	// Parse the template using the provided template parameter
	tmpl, err := template.New("email").Parse(templateStr)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	// Execute the template with the custom data
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	// Send the email based on configuration
	if s.Config.UseTLS {
		return s.sendWithTLS(to, body.Bytes())
	} else {
		return s.sendWithSTARTTLS(to, body.Bytes())
	}
}

// sendWithTLS sends email using TLS from the start (port 465)
func (s *Sender) sendWithTLS(to string, body []byte) (err error) {
	addr := fmt.Sprintf("%s:%d", s.Config.Host, s.Config.Port)

	// Create TLS configuration
	tlsConfig := &tls.Config{
		ServerName:         s.Config.Host,
		InsecureSkipVerify: s.Config.SkipTLSVerify,
	}

	// Dial with TLS
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect with TLS: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close TLS connection: %w", closeErr)
		}
	}()

	// Create an SMTP client
	client, err := smtp.NewClient(conn, s.Config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer func() {
		if quitErr := client.Quit(); quitErr != nil && err == nil {
			err = fmt.Errorf("failed to quit SMTP client: %w", quitErr)
		}
	}()

	// Authenticate
	auth := smtp.PlainAuth("", s.Config.Username, s.Config.Password, s.Config.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP authentication failed: %w", err)
	}

	// Set sender
	if err := client.Mail(s.Config.From); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipient
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	// Send message
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	defer func() {
		if closeErr := writer.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close data writer: %w", closeErr)
		}
	}()

	if _, err := writer.Write(body); err != nil {
		return fmt.Errorf("failed to write message body: %w", err)
	}

	return nil
}

// sendWithSTARTTLS sends email using STARTTLS (port 587)
func (s *Sender) sendWithSTARTTLS(to string, body []byte) error {
	// Set up authentication
	auth := smtp.PlainAuth("", s.Config.Username, s.Config.Password, s.Config.Host)

	// Send the email
	addr := fmt.Sprintf("%s:%d", s.Config.Host, s.Config.Port)
	err := smtp.SendMail(addr, auth, s.Config.From, []string{to}, body)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
