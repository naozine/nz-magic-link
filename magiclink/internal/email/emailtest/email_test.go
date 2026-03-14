package email_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/naozine/nz-magic-link/magiclink/internal/email"
)

// receivedMessage holds the captured email data from the test SMTP server.
type receivedMessage struct {
	From string
	To   []string
	Data []byte
}

// testBackend implements smtp.Backend for testing.
type testBackend struct {
	mu       sync.Mutex
	messages []receivedMessage
	username string
	password string
}

func (b *testBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &testSession{backend: b}, nil
}

// testSession implements smtp.Session.
type testSession struct {
	backend *testBackend
	from    string
	to      []string
}

func (s *testSession) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *testSession) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if username != s.backend.username || password != s.backend.password {
			return &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Invalid credentials"}
		}
		return nil
	}), nil
}

func (s *testSession) Mail(from string, opts *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *testSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *testSession) Data(r io.Reader) error {
	buf, _ := io.ReadAll(r)
	s.backend.mu.Lock()
	s.backend.messages = append(s.backend.messages, receivedMessage{
		From: s.from,
		To:   s.to,
		Data: buf,
	})
	s.backend.mu.Unlock()
	return nil
}

func (s *testSession) Reset() {}
func (s *testSession) Logout() error { return nil }

// generateTestTLSConfig creates a self-signed certificate for testing.
func generateTestTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// startTestSMTPServer starts an in-process SMTP server for testing.
// If implicitTLS is true, the listener uses TLS from the start (port 465 equivalent).
// Otherwise, the server advertises STARTTLS (port 587 equivalent).
func startTestSMTPServer(t *testing.T, tlsConfig *tls.Config, implicitTLS bool) (addr string, backend *testBackend) {
	t.Helper()

	backend = &testBackend{
		username: "testuser",
		password: "testpass",
	}

	s := smtp.NewServer(backend)
	s.TLSConfig = tlsConfig

	var ln net.Listener
	var err error

	if implicitTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}

	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { _ = s.Close() })

	return ln.Addr().String(), backend
}

func TestSendMagicLink_TLS(t *testing.T) {
	tlsConfig, err := generateTestTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	addr, backend := startTestSMTPServer(t, tlsConfig, true)
	host, port := splitHostPort(t, addr)

	sender := email.New(email.Config{
		Host:          host,
		Port:          port,
		Username:      "testuser",
		Password:      "testpass",
		From:          "noreply@example.com",
		FromName:      "Test App",
		VerifyURL:     "/auth/verify",
		ServerAddr:    "https://example.com",
		UseTLS:        true,
		SkipTLSVerify: true,
	})

	err = sender.SendMagicLink("user@example.com", "test-token-123", 30)
	if err != nil {
		t.Fatalf("SendMagicLink failed: %v", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	if len(backend.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(backend.messages))
	}

	msg := backend.messages[0]
	if msg.From != "noreply@example.com" {
		t.Errorf("unexpected From: %s", msg.From)
	}
	if len(msg.To) != 1 || msg.To[0] != "user@example.com" {
		t.Errorf("unexpected To: %v", msg.To)
	}

	body := string(msg.Data)
	if !strings.Contains(body, "https://example.com/auth/verify?token=test-token-123") {
		t.Errorf("body missing magic link: %s", body)
	}
	if !strings.Contains(body, "30 minutes") {
		t.Errorf("body missing expiry: %s", body)
	}
}

func TestSendMagicLink_STARTTLS(t *testing.T) {
	tlsConfig, err := generateTestTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	addr, backend := startTestSMTPServer(t, tlsConfig, false)
	_, port := splitHostPort(t, addr)

	sender := email.New(email.Config{
		Host:          "localhost",
		Port:          port,
		Username:      "testuser",
		Password:      "testpass",
		From:          "noreply@example.com",
		FromName:      "Test App",
		VerifyURL:     "/auth/verify",
		ServerAddr:    "https://example.com",
		UseSTARTTLS:   true,
		SkipTLSVerify: true,
	})

	err = sender.SendMagicLink("user@example.com", "test-token-456", 15)
	if err != nil {
		t.Fatalf("SendMagicLink failed: %v", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	if len(backend.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(backend.messages))
	}

	msg := backend.messages[0]
	if msg.From != "noreply@example.com" {
		t.Errorf("unexpected From: %s", msg.From)
	}

	body := string(msg.Data)
	if !strings.Contains(body, "https://example.com/auth/verify?token=test-token-456") {
		t.Errorf("body missing magic link: %s", body)
	}
}

func TestSendMagicLink_TLS_AuthFailure(t *testing.T) {
	tlsConfig, err := generateTestTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	addr, _ := startTestSMTPServer(t, tlsConfig, true)
	host, port := splitHostPort(t, addr)

	sender := email.New(email.Config{
		Host:          host,
		Port:          port,
		Username:      "testuser",
		Password:      "wrongpass",
		From:          "noreply@example.com",
		FromName:      "Test App",
		VerifyURL:     "/auth/verify",
		ServerAddr:    "https://example.com",
		UseTLS:        true,
		SkipTLSVerify: true,
	})

	err = sender.SendMagicLink("user@example.com", "token", 30)
	if err == nil {
		t.Fatal("expected authentication error, got nil")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSendMagicLink_NonASCII(t *testing.T) {
	tlsConfig, err := generateTestTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	addr, backend := startTestSMTPServer(t, tlsConfig, true)
	host, port := splitHostPort(t, addr)

	sender := email.New(email.Config{
		Host:          host,
		Port:          port,
		Username:      "testuser",
		Password:      "testpass",
		From:          "noreply@example.com",
		FromName:      "テストアプリ",
		Subject:       "認証リンク",
		VerifyURL:     "/auth/verify",
		ServerAddr:    "https://example.com",
		UseTLS:        true,
		SkipTLSVerify: true,
	})

	err = sender.SendMagicLink("user@example.com", "token-jp", 30)
	if err != nil {
		t.Fatalf("SendMagicLink failed: %v", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	body := string(backend.messages[0].Data)
	// MIME B-encoded FromName and Subject should be present
	if !strings.Contains(body, "=?UTF-8?b?") {
		t.Errorf("expected MIME B-encoded non-ASCII content in body: %s", body)
	}
}

func TestSendMagicLink_CustomTemplate(t *testing.T) {
	tlsConfig, err := generateTestTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	addr, backend := startTestSMTPServer(t, tlsConfig, true)
	host, port := splitHostPort(t, addr)

	sender := email.New(email.Config{
		Host:          host,
		Port:          port,
		Username:      "testuser",
		Password:      "testpass",
		From:          "noreply@example.com",
		FromName:      "Test App",
		VerifyURL:     "/auth/verify",
		ServerAddr:    "https://example.com",
		UseTLS:        true,
		SkipTLSVerify: true,
	})

	type CustomData struct {
		email.BaseTemplateData
		AppName string
	}

	customTemplate := `From: {{.FromName}} <{{.From}}>
To: {{.To}}
Subject: {{.Subject}}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Welcome to {{.AppName}}!
Click here: {{.MagicLink}}
`
	data := &CustomData{AppName: "MyApp"}
	_, err = sender.SendMagicLinkWithTemplateAndData("user@example.com", "token-custom", 30, "Welcome", customTemplate, data, false)
	if err != nil {
		t.Fatalf("SendMagicLinkWithTemplateAndData failed: %v", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	body := string(backend.messages[0].Data)
	if !strings.Contains(body, "Welcome to MyApp!") {
		t.Errorf("body missing custom content: %s", body)
	}
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}
