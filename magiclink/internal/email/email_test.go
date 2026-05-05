package email

import (
	"strings"
	"testing"
)

// baseSenderConfig returns a Config suitable for dry-run tests.
func baseSenderConfig() Config {
	return Config{
		Host:       "smtp.example.com",
		Port:       587,
		Username:   "user",
		Password:   "pass",
		From:       "noreply@example.com",
		FromName:   "Test App",
		ServerAddr: "https://example.com",
		VerifyURL:  "/auth/verify",
	}
}

// minimalTemplate is a simple template that exposes the URL and expiry for assertions.
const minimalTemplate = `From: {{.FromName}} <{{.From}}>
To: {{.To}}
Subject: {{.Subject}}

Link: {{.MagicLink}}
Expires: {{.ExpiryMinutes}} minutes.
`

// --- New ---

func TestNew_DefaultsTemplateWhenEmpty(t *testing.T) {
	s := New(Config{})
	if s.Config.Template != DefaultTemplate {
		t.Error("expected DefaultTemplate to be applied when none provided")
	}
}

func TestNew_PreservesCustomTemplate(t *testing.T) {
	custom := "custom: {{.MagicLink}}"
	s := New(Config{Template: custom})
	if s.Config.Template != custom {
		t.Error("expected custom template to be preserved")
	}
}

// --- Input validation ---

func TestSendMagicLinkWithTemplateAndData_RejectsNonStruct(t *testing.T) {
	s := New(baseSenderConfig())
	notAStruct := "string-not-struct"

	_, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Subj", minimalTemplate, notAStruct, true, "")
	if err == nil {
		t.Fatal("expected error when data is not a struct")
	}
	if !strings.Contains(err.Error(), "must be a struct") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSendMagicLinkWithTemplateAndData_RejectsMissingBaseTemplateData(t *testing.T) {
	s := New(baseSenderConfig())
	type NoEmbed struct {
		Name string
	}
	_, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Subj", minimalTemplate, &NoEmbed{}, true, "")
	if err == nil {
		t.Fatal("expected error when struct does not embed BaseTemplateData")
	}
	if !strings.Contains(err.Error(), "BaseTemplateData") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- MagicLink URL construction ---

func TestSendMagicLinkWithTemplateAndData_BuildsMagicLinkURL(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}

	body, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "abc123", 30, "Subj", minimalTemplate, data, true, "")
	if err != nil {
		t.Fatal(err)
	}
	expected := "https://example.com/auth/verify?token=abc123"
	if !strings.Contains(body, expected) {
		t.Errorf("expected body to contain %q, got: %s", expected, body)
	}
}

func TestSendMagicLinkWithTemplateAndData_AppendsRedirectParam(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}

	body, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Subj", minimalTemplate, data, true, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "?token=tok&redirect=") {
		t.Errorf("expected redirect parameter, got: %s", body)
	}
	if !strings.Contains(body, "redirect=%2Fdashboard") {
		t.Errorf("expected redirect to be URL-encoded as %%2Fdashboard, got: %s", body)
	}
}

func TestSendMagicLinkWithTemplateAndData_NoRedirectIfEmpty(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}

	body, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Subj", minimalTemplate, data, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "redirect=") {
		t.Errorf("expected no redirect parameter when redirectPath is empty, got: %s", body)
	}
}

func TestSendMagicLinkWithTemplateAndData_RedirectIsURLEncoded(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}

	// Path with characters that require encoding
	body, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Subj", minimalTemplate, data, true, "/path with spaces?x=1&y=2")
	if err != nil {
		t.Fatal(err)
	}
	// "/path with spaces?x=1&y=2" → URL-encoded
	if !strings.Contains(body, "%2Fpath+with+spaces%3Fx%3D1%26y%3D2") {
		t.Errorf("expected URL-encoded redirect path, got: %s", body)
	}
}

// --- MIME encoding ---

func TestSendMagicLinkWithTemplateAndData_NonASCIIFromName_BEncoded(t *testing.T) {
	cfg := baseSenderConfig()
	cfg.FromName = "テストアプリ" // non-ASCII
	s := New(cfg)
	data := &struct{ BaseTemplateData }{}

	body, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Subj", minimalTemplate, data, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "=?UTF-8?b?") {
		t.Errorf("expected MIME B-encoded FromName, got: %s", body)
	}
}

func TestSendMagicLinkWithTemplateAndData_NonASCIISubject_BEncoded(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}

	body, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "認証リンク", minimalTemplate, data, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "=?UTF-8?b?") {
		t.Errorf("expected MIME B-encoded Subject, got: %s", body)
	}
}

func TestSendMagicLinkWithTemplateAndData_ASCIINotEncoded(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}

	body, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Plain Subject", minimalTemplate, data, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "=?UTF-8?b?") {
		t.Errorf("expected no MIME encoding for ASCII content, got: %s", body)
	}
	if !strings.Contains(body, "Subject: Plain Subject") {
		t.Errorf("expected Plain Subject verbatim, got: %s", body)
	}
	if !strings.Contains(body, "From: Test App <") {
		t.Errorf("expected ASCII FromName verbatim, got: %s", body)
	}
}

// --- Template population ---

func TestSendMagicLinkWithTemplateAndData_PopulatesBaseTemplateData(t *testing.T) {
	s := New(baseSenderConfig())

	// Custom struct with extra field; verify both base fields and custom field render
	type CustomData struct {
		BaseTemplateData
		AppName string
	}
	tmpl := `Hi from {{.AppName}}, link={{.MagicLink}}, to={{.To}}, expires={{.ExpiryMinutes}}`
	data := &CustomData{AppName: "MyApp"}

	body, err := s.SendMagicLinkWithTemplateAndData("user@example.com", "tok", 42, "Subj", tmpl, data, true, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Hi from MyApp", "to=user@example.com", "expires=42", "link=https://example.com/auth/verify?token=tok"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected body to contain %q, got: %s", want, body)
		}
	}
}

func TestSendMagicLinkWithTemplateAndData_ExpiryMinutesInTemplate(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}
	tmpl := `Expires: {{.ExpiryMinutes}}`

	body, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 7, "Subj", tmpl, data, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "Expires: 7") {
		t.Errorf("expected ExpiryMinutes 7, got: %s", body)
	}
}

// --- Template errors ---

func TestSendMagicLinkWithTemplateAndData_TemplateParseError(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}
	bad := `unclosed action: {{.MagicLink`

	_, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Subj", bad, data, true, "")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSendMagicLinkWithTemplateAndData_TemplateExecError(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}
	// Reference a field that doesn't exist on the data struct
	bad := `{{.NonExistentField}}`

	_, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Subj", bad, data, true, "")
	if err == nil {
		t.Fatal("expected execution error")
	}
	if !strings.Contains(err.Error(), "execute") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- dryRun behavior ---

func TestSendMagicLinkWithTemplateAndData_DryRunReturnsExpandedTemplate(t *testing.T) {
	s := New(baseSenderConfig())
	data := &struct{ BaseTemplateData }{}

	body, err := s.SendMagicLinkWithTemplateAndData("u@example.com", "tok", 30, "Subj", minimalTemplate, data, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if body == "" {
		t.Fatal("expected non-empty body in dry-run mode")
	}
	// Expanded body should include both header and link content
	if !strings.Contains(body, "Subject: Subj") {
		t.Errorf("expected Subject header, got: %s", body)
	}
	if !strings.Contains(body, "Link: https://example.com/auth/verify?token=tok") {
		t.Errorf("expected expanded link, got: %s", body)
	}
}
