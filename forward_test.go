package streamer

import (
	"strings"
	"testing"
	"time"
)

func TestLogLevelStringToSyslog(t *testing.T) {
	tests := []struct {
		level string
		want  int
	}{
		{"debug", 7},
		{"info", 6},
		{"INFO", 6},
		{"warn", 4},
		{"error", 3},
		{"ERROR", 3},
		{"fatal", 2},
		{"panic", 1},
		{"something-else", 6},
		{"", 6},
	}

	for _, tt := range tests {
		if got := logLevelStringToSyslog(tt.level); got != tt.want {
			t.Errorf("logLevelStringToSyslog(%q) = %d, want %d", tt.level, got, tt.want)
		}
	}
}

func TestAuditEventFieldsToMap(t *testing.T) {
	with := With(AuditEventLoginStandard)
	event := &AuditEvent{
		CorrelationID: "abc",
		AuthorName:    "juan",
		With:          &with,
	}

	fields := auditEventFieldsToMap(event)

	if fields["CorrelationID"] != "abc" {
		t.Errorf("CorrelationID = %q", fields["CorrelationID"])
	}
	if fields["AuthorName"] != "juan" {
		t.Errorf("AuthorName = %q", fields["AuthorName"])
	}
	// Non-nil pointers must be dereferenced, not rendered as addresses.
	if fields["With"] != string(AuditEventLoginStandard) {
		t.Errorf("With = %q, want %q", fields["With"], AuditEventLoginStandard)
	}
	// Nil pointers must be omitted entirely.
	if _, ok := fields["CustomMessage"]; ok {
		t.Errorf("nil pointer field CustomMessage should be absent, got %q", fields["CustomMessage"])
	}
}

func TestAuthEventFieldsToMap(t *testing.T) {
	message := "Failed to authenticate"
	event := &AuthEvent{
		CorrelationID: "xyz",
		Severity:      "ERROR",
		Message:       &message,
	}

	fields := authEventFieldsToMap(event)

	if fields["Message"] != message {
		t.Errorf("Message = %q, want %q", fields["Message"], message)
	}
	if _, ok := fields["RemoteIP"]; ok {
		t.Errorf("nil pointer field RemoteIP should be absent")
	}
}

func TestAuditEventToSyslogMessage(t *testing.T) {
	s := &GitLabLogStreamer{
		cfg: Config{GitlabHostname: "gitlab.example.com"},
	}

	with := With(AuditEventLoginStandard)
	event := &AuditEvent{
		CorrelationID: "abc",
		Severity:      "INFO",
		Time:          time.Date(2024, 4, 16, 10, 0, 0, 0, time.UTC),
		AuthorName:    "juan",
		EntityType:    AuthorClassUser,
		With:          &with,
	}

	msg := s.auditEventToSyslogMessage(event)

	str, err := msg.String()
	if err != nil {
		t.Fatalf("syslog message String() error = %v", err)
	}

	// facility 13, severity info (6) => priority 110
	if !strings.HasPrefix(str, "<110>1 ") {
		t.Errorf("message %q does not start with expected priority header", str)
	}
	// The msg ID is sanitized to a space-free RFC5424 MSGID ("User-logged-in")
	// so it now survives serialization, alongside the free-form message.
	for _, want := range []string{"gitlab.example.com", "gitlab", "User-logged-in", "AuthorName=\"juan\"", "User juan logged in"} {
		if !strings.Contains(str, want) {
			t.Errorf("message %q does not contain %q", str, want)
		}
	}
}

func TestToSyslogMsgID(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"User logged in", "User-logged-in"},
		{"User logged in with OpenID Connect", "User-logged-in-with-OpenID-Conne"}, // truncated to 32
		{"", "-"},
		{"already-valid", "already-valid"},
		{"weird\tchars\nhere", "weirdcharshere"},
	}

	for _, tt := range tests {
		got := toSyslogMsgID(tt.in)
		if got != tt.want {
			t.Errorf("toSyslogMsgID(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if len(got) > 32 {
			t.Errorf("toSyslogMsgID(%q) length %d exceeds 32", tt.in, len(got))
		}
		if strings.ContainsAny(got, " \t\n") {
			t.Errorf("toSyslogMsgID(%q) = %q contains whitespace", tt.in, got)
		}
	}
}

func TestAuditEventToLEEF(t *testing.T) {
	s := &GitLabLogStreamer{
		cfg:                  Config{GitlabHostname: "gitlab.example.com"},
		currentGitlabVersion: "16.9.1",
	}

	with := With(AuditEventLoginStandard)
	event := &AuditEvent{
		CorrelationID: "abc",
		Severity:      "INFO",
		Time:          time.Date(2024, 4, 16, 10, 0, 0, 0, time.UTC),
		AuthorName:    "juan",
		EntityType:    AuthorClassUser,
		With:          &with,
	}

	str := s.auditEventToLEEF(event).String()

	wantPrefix := "<110>1 2024-04-16T10:00:00Z gitlab.example.com LEEF:2.0|GitLab Inc.|GitLab|16.9.1|User logged in|^|"
	if !strings.HasPrefix(str, wantPrefix) {
		t.Errorf("LEEF message %q does not start with %q", str, wantPrefix)
	}
	if !strings.Contains(str, "AuthorName=juan") {
		t.Errorf("LEEF message %q missing AuthorName attribute", str)
	}
}
