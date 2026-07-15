package streamer

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureForwardTarget starts a test HTTP server that records the requests it
// receives and replies with status.
func captureForwardTarget(t *testing.T, status int) (*httptest.Server, *[]*http.Request, *[][]byte) {
	t.Helper()

	reqs := &[]*http.Request{}
	bodies := &[][]byte{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*reqs = append(*reqs, r.Clone(r.Context()))
		*bodies = append(*bodies, body)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)

	return srv, reqs, bodies
}

func TestForwardNewAuditLogEventsHTTPSendsConfiguredHeaders(t *testing.T) {
	srv, reqs, bodies := captureForwardTarget(t, http.StatusOK)

	s := &GitLabLogStreamer{
		cfg: Config{
			AuditLogForwardingEndpoint: srv.URL,
			// Viper lowercases config map keys, so headers arrive lowercased;
			// http.Header.Set canonicalizes them on the way out.
			HTTPHeaders: map[string]string{
				"authorization": "Bearer 1234567890",
				"x-custom":      "yes",
			},
		},
	}

	event := &AuditEvent{CorrelationID: "abc", AuthorName: "juan"}
	if err := s.forwardNewAuditLogEventsHTTP([]*AuditEvent{event}); err != nil {
		t.Fatalf("forwardNewAuditLogEventsHTTP() error = %v", err)
	}

	if len(*reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*reqs))
	}
	req := (*reqs)[0]

	if req.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", req.Method)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer 1234567890" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer 1234567890")
	}
	if got := req.Header.Get("X-Custom"); got != "yes" {
		t.Errorf("X-Custom header = %q, want %q", got, "yes")
	}
	if got := req.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type header = %q, want application/json", got)
	}

	var decoded AuditEvent
	if err := json.Unmarshal((*bodies)[0], &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if decoded.CorrelationID != "abc" {
		t.Errorf("forwarded CorrelationID = %q, want %q", decoded.CorrelationID, "abc")
	}
}

func TestForwardHTTPDefaultsContentTypeWithoutConfiguredHeaders(t *testing.T) {
	srv, reqs, _ := captureForwardTarget(t, http.StatusOK)

	s := &GitLabLogStreamer{cfg: Config{AuditLogForwardingEndpoint: srv.URL}}

	if err := s.forwardNewAuditLogEventsHTTP([]*AuditEvent{{CorrelationID: "abc"}}); err != nil {
		t.Fatalf("forwardNewAuditLogEventsHTTP() error = %v", err)
	}

	if len(*reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*reqs))
	}
	if got := (*reqs)[0].Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type header = %q, want application/json", got)
	}
}

func TestForwardHTTPConfiguredContentTypeOverridesDefault(t *testing.T) {
	srv, reqs, _ := captureForwardTarget(t, http.StatusOK)

	s := &GitLabLogStreamer{
		cfg: Config{
			AuditLogForwardingEndpoint: srv.URL,
			HTTPHeaders:                map[string]string{"content-type": "application/vnd.custom+json"},
		},
	}

	if err := s.forwardNewAuditLogEventsHTTP([]*AuditEvent{{CorrelationID: "abc"}}); err != nil {
		t.Fatalf("forwardNewAuditLogEventsHTTP() error = %v", err)
	}

	if got := (*reqs)[0].Header.Get("Content-Type"); got != "application/vnd.custom+json" {
		t.Errorf("Content-Type header = %q, want the configured override", got)
	}
	// The default must not linger as a second value.
	if vals := (*reqs)[0].Header.Values("Content-Type"); len(vals) != 1 {
		t.Errorf("Content-Type has %d values (%v), want exactly 1", len(vals), vals)
	}
}

func TestForwardNewAuthEventsHTTPSendsConfiguredHeaders(t *testing.T) {
	srv, reqs, bodies := captureForwardTarget(t, http.StatusOK)

	s := &GitLabLogStreamer{
		cfg: Config{
			AuthLogForwardingEndpoint: srv.URL,
			HTTPHeaders:               map[string]string{"authorization": "Bearer authtoken"},
		},
	}

	message := "Failed to authenticate"
	event := &AuthEvent{CorrelationID: "xyz", Message: &message}
	if err := s.forwardNewAuthEventsHTTP([]*AuthEvent{event}); err != nil {
		t.Fatalf("forwardNewAuthEventsHTTP() error = %v", err)
	}

	if len(*reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(*reqs))
	}
	if got := (*reqs)[0].Header.Get("Authorization"); got != "Bearer authtoken" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer authtoken")
	}

	var decoded AuthEvent
	if err := json.Unmarshal((*bodies)[0], &decoded); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if decoded.CorrelationID != "xyz" {
		t.Errorf("forwarded CorrelationID = %q, want %q", decoded.CorrelationID, "xyz")
	}
}

func TestForwardHTTPForwardsEveryEvent(t *testing.T) {
	srv, reqs, _ := captureForwardTarget(t, http.StatusOK)

	s := &GitLabLogStreamer{cfg: Config{AuditLogForwardingEndpoint: srv.URL}}

	events := []*AuditEvent{{CorrelationID: "a"}, {CorrelationID: "b"}, {CorrelationID: "c"}}
	if err := s.forwardNewAuditLogEventsHTTP(events); err != nil {
		t.Fatalf("forwardNewAuditLogEventsHTTP() error = %v", err)
	}

	if len(*reqs) != len(events) {
		t.Errorf("got %d requests, want %d", len(*reqs), len(events))
	}
}

func TestForwardHTTPNonSuccessStatusIsBestEffort(t *testing.T) {
	srv, reqs, _ := captureForwardTarget(t, http.StatusInternalServerError)

	s := &GitLabLogStreamer{cfg: Config{AuditLogForwardingEndpoint: srv.URL}}

	// Forwarding is best-effort: a rejecting endpoint is logged, not fatal,
	// and must not stop the remaining events.
	events := []*AuditEvent{{CorrelationID: "a"}, {CorrelationID: "b"}}
	if err := s.forwardNewAuditLogEventsHTTP(events); err != nil {
		t.Fatalf("forwardNewAuditLogEventsHTTP() should tolerate non-2xx, got error = %v", err)
	}
	if len(*reqs) != 2 {
		t.Errorf("got %d requests, want 2 (a 500 must not abort the loop)", len(*reqs))
	}
}

func TestPostEventJSONReturnsErrorOnNonSuccessStatus(t *testing.T) {
	srv, _, _ := captureForwardTarget(t, http.StatusUnauthorized)

	s := &GitLabLogStreamer{}
	err := s.postEventJSON(&http.Client{Timeout: 5 * time.Second}, srv.URL, []byte(`{}`))
	if err == nil {
		t.Fatal("postEventJSON() expected an error for a 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q should mention the status code", err)
	}
}

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
