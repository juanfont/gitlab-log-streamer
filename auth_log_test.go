package streamer

import (
	"testing"
)

const sampleAuthLine = `{"severity":"ERROR","time":"2024-04-16T10:00:00.000Z","correlation_id":"01HVNJ0000000000000000000B","message":"Failed to authenticate","env":"production","remote_ip":"192.0.2.1","request_method":"POST","path":"/users/sign_in","meta.feature_category":"system_access"}`

func TestParseAuthEvent(t *testing.T) {
	s := &GitLabLogStreamer{}

	event, err := s.parseAuthEvent(sampleAuthLine)
	if err != nil {
		t.Fatalf("parseAuthEvent() error = %v", err)
	}

	if event.CorrelationID != "01HVNJ0000000000000000000B" {
		t.Errorf("CorrelationID = %q", event.CorrelationID)
	}
	if event.Severity != "ERROR" {
		t.Errorf("Severity = %q", event.Severity)
	}
	if event.Message == nil || *event.Message != "Failed to authenticate" {
		t.Errorf("Message = %v", event.Message)
	}
	if event.RemoteIP == nil || *event.RemoteIP != "192.0.2.1" {
		t.Errorf("RemoteIP = %v", event.RemoteIP)
	}
}

func TestParseAuthEventInvalidJSON(t *testing.T) {
	s := &GitLabLogStreamer{}

	if _, err := s.parseAuthEvent("{broken"); err == nil {
		t.Error("parseAuthEvent() expected error for invalid JSON")
	}
}

func TestGetAuthEventMessageType(t *testing.T) {
	message := "Failed to authenticate"
	category := "system_access"

	tests := []struct {
		name  string
		event *AuthEvent
		want  string
	}{
		{
			name:  "message takes precedence",
			event: &AuthEvent{Message: &message, MetaFeatureCategory: &category},
			want:  message,
		},
		{
			name:  "falls back to feature category",
			event: &AuthEvent{MetaFeatureCategory: &category},
			want:  category,
		},
		{
			name:  "unknown when both missing",
			event: &AuthEvent{},
			want:  "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAuthEventMessageType(tt.event); got != tt.want {
				t.Errorf("getAuthEventMessageType() = %q, want %q", got, tt.want)
			}
		})
	}
}
