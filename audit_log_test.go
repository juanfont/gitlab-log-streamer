package streamer

import (
	"strings"
	"testing"
	"time"
)

const sampleAuditLoginLine = `{"severity":"INFO","time":"2024-04-16T10:00:00.000Z","correlation_id":"01HVNJ0000000000000000000A","author_id":1,"author_name":"juan","entity_id":1,"entity_type":"User","ip_address":"192.0.2.1","with":"standard","target_id":1,"target_type":"User","target_details":"juan","entity_path":"juan","meta.caller_id":"SessionsController#create"}`

func TestParseAuditLogEvent(t *testing.T) {
	s := &GitLabLogStreamer{}

	event, err := s.parseAuditLogEvent(sampleAuditLoginLine)
	if err != nil {
		t.Fatalf("parseAuditLogEvent() error = %v", err)
	}

	if event.CorrelationID != "01HVNJ0000000000000000000A" {
		t.Errorf("CorrelationID = %q", event.CorrelationID)
	}
	if event.AuthorName != "juan" {
		t.Errorf("AuthorName = %q", event.AuthorName)
	}
	if event.EntityType != AuthorClassUser {
		t.Errorf("EntityType = %q", event.EntityType)
	}
	if event.With == nil || *event.With != With(AuditEventLoginStandard) {
		t.Errorf("With = %v, want %q", event.With, AuditEventLoginStandard)
	}
	wantTime := time.Date(2024, 4, 16, 10, 0, 0, 0, time.UTC)
	if !event.Time.Equal(wantTime) {
		t.Errorf("Time = %v, want %v", event.Time, wantTime)
	}
}

func TestParseAuditLogEventInvalidJSON(t *testing.T) {
	s := &GitLabLogStreamer{}

	if _, err := s.parseAuditLogEvent("not json"); err == nil {
		t.Error("parseAuditLogEvent() expected error for invalid JSON")
	}
}

func TestGetAuditEventMessageTypeUserLogins(t *testing.T) {
	tests := []struct {
		with        string
		wantMsgID   string
		wantContain string
	}{
		{AuditEventLoginStandard, "User logged in", "juan logged in"},
		{AuditEventLoginWithTwoFactor, "User logged in with 2FA", "two-factor"},
		{AuditEventLoginWithU2F, "User logged in with U2F", "U2F"},
		{AuditEventLoginWithWebAuthn, "User logged in with WebAuthn", "WebAuthn"},
		{"saml", "User logged in with SAML", "SAML"},
		{"openid_connect", "User logged in with OpenID Connect", "OpenID Connect"},
		{"carrier-pigeon", "User logged in with unknown method", "carrier-pigeon"},
	}

	for _, tt := range tests {
		t.Run(tt.with, func(t *testing.T) {
			with := With(tt.with)
			event := &AuditEvent{
				EntityType: AuthorClassUser,
				AuthorName: "juan",
				With:       &with,
			}

			msgID, msg := getAuditEventMessageType(event)
			if msgID != tt.wantMsgID {
				t.Errorf("message ID = %q, want %q", msgID, tt.wantMsgID)
			}
			if !strings.Contains(msg, tt.wantContain) {
				t.Errorf("message %q does not contain %q", msg, tt.wantContain)
			}
		})
	}
}

func TestGetAuditEventMessageTypeProject(t *testing.T) {
	add := Add("project")
	event := &AuditEvent{
		EntityType: AuthorClassProject,
		AuthorName: "juan",
		EntityPath: "group/repo",
		Add:        &add,
	}

	msgID, msg := getAuditEventMessageType(event)
	if msgID != "Project event - add" {
		t.Errorf("message ID = %q", msgID)
	}
	if !strings.Contains(msg, "group/repo") {
		t.Errorf("message %q does not mention the entity path", msg)
	}
}

func TestGetAuditEventMessageTypeGroup(t *testing.T) {
	remove := Add("user_access")
	details := "someone"
	event := &AuditEvent{
		EntityType:    AuthorClassGroup,
		AuthorName:    "juan",
		EntityID:      42,
		EntityPath:    "group",
		Remove:        &remove,
		TargetDetails: &details,
	}

	msgID, msg := getAuditEventMessageType(event)
	if msgID != "Group event - remove" {
		t.Errorf("message ID = %q", msgID)
	}
	if !strings.Contains(msg, "user_access") || !strings.Contains(msg, "someone") {
		t.Errorf("message %q missing expected details", msg)
	}
}

func TestGetAuditEventMessageTypeUnknownEntity(t *testing.T) {
	event := &AuditEvent{EntityType: "Wormhole"}

	msgID, _ := getAuditEventMessageType(event)
	if msgID != "unknown event" {
		t.Errorf("message ID = %q, want %q", msgID, "unknown event")
	}
}
