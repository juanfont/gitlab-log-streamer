package streamer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	AuditEventLoginWithTwoFactor = "two-factor"
	AuditEventLoginWithU2F       = "two-factor-via-u2f-device"
	AuditEventLoginWithWebAuthn  = "two-factor-via-webauthn-device"
	AuditEventLoginStandard      = "standard"
)

func (s *GitLabLogStreamer) readAuditLogFile() error {
	content, err := os.ReadFile(s.cfg.AuditLogPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	auditEvents := []*AuditEvent{}

	for _, line := range lines {
		if line == "" {
			log.Warn().Msg("Empty line in audit log")
			continue
		}

		auditEvent, err := s.parseAuditLogEvent(line)
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to parse audit log entry. Content: %s", line)
			continue
		}

		auditEvents = append(auditEvents, auditEvent)
	}

	newEvents, err := s.processNewAuditLogEvents(auditEvents)
	if err != nil {
		return err
	}

	err = s.forwardNewAuditLogEvents(newEvents)
	if err != nil {
		return err
	}

	return nil
}

func (s *GitLabLogStreamer) forwardNewAuditLogEvents(auditEvents []*AuditEvent) error {
	if s.cfg.AuditLogForwardingEndpoint != "" {
		log.Info().Msgf("Forwarding %d audit events to HTTP endpoint %s", len(auditEvents), s.cfg.AuditLogForwardingEndpoint)
		err := s.forwardNewAuditLogEventsHTTP(auditEvents)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to forward audit events to HTTP endpoint")
		}
	}

	if s.cfg.SyslogServerAddr != "" {
		err := s.forwardNewAuditLogEventsSyslog(auditEvents)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to forward audit events to syslog server")
		}
	}

	return nil
}

func (s *GitLabLogStreamer) processNewAuditLogEvents(auditEvents []*AuditEvent) ([]*AuditEvent, error) {
	newEvents := []*AuditEvent{}

	for _, auditEvent := range auditEvents {
		// check if the auditEvent correlation ID already exists
		// if it does, we skip it
		// if it doesn't, we insert it

		_, ok := s.latestAuditLogEvents.Load(fmt.Sprintf("%s,%d", auditEvent.CorrelationID, auditEvent.Time.UnixNano()))
		if ok {
			log.Debug().Msgf("Audit event with correlation ID %s at %s already exists. Skipping", auditEvent.CorrelationID, auditEvent.Time.Format(time.RFC3339))
			continue
		}

		err := s.db.Create(auditEvent).Error
		if err != nil {
			log.Error().Err(err).Msgf("Failed to insert audit event with correlation ID %s", auditEvent.CorrelationID)
			return newEvents, err
		}

		s.latestAuditLogEvents.Store(fmt.Sprintf("%s,%d", auditEvent.CorrelationID, auditEvent.Time.UnixNano()), *auditEvent)
		newEvents = append(newEvents, auditEvent)
		auditLogEventsReceived.Inc()
		log.Info().Msgf("Inserted audit event with correlation ID %s", auditEvent.CorrelationID)
	}

	log.Info().Msgf("Inserted %d new audit events", len(newEvents))

	return newEvents, nil
}

func (s *GitLabLogStreamer) parseAuditLogEvent(line string) (*AuditEvent, error) {
	auditEvent := &AuditEvent{}

	err := json.Unmarshal([]byte(line), auditEvent)
	if err != nil {
		return nil, err
	}

	return auditEvent, nil
}

// auditEventToMessage converts an audit event to a human-readable message
func getAuditEventMessageType(auditEvent *AuditEvent) (string, string) {
	if auditEvent.EntityType == "User" {
		return auditEventToUserMessageType(auditEvent)
	}

	if auditEvent.EntityType == "Project" {
		return auditEventToProjectMessageType(auditEvent)
	}

	if auditEvent.EntityType == "Group" {
		return auditEventToGroupMessageType(auditEvent)
	}

	log.Warn().Msgf("Unknown audit event entity type %s", auditEvent.EntityType)

	return "unknown event", fmt.Sprintf("Unknown event: %v", auditEvent)
}

func auditEventToUserMessageType(auditEvent *AuditEvent) (string, string) {
	if auditEvent.With != nil {
		switch *auditEvent.With {
		case AuditEventLoginWithWebAuthn:
			return "User logged in with WebAuthn", fmt.Sprintf("User %s logged in with WebAuthn", auditEvent.AuthorName)
		case AuditEventLoginWithU2F:
			return "User logged in with U2F", fmt.Sprintf("User %s logged in with U2F", auditEvent.AuthorName)
		case AuditEventLoginWithTwoFactor:
			return "User logged in with 2FA", fmt.Sprintf("User %s logged in with two-factor authentication", auditEvent.AuthorName)
		case AuditEventLoginStandard:
			return "User logged in", fmt.Sprintf("User %s logged in", auditEvent.AuthorName)
		case "saml":
			return "User logged in with SAML", fmt.Sprintf("User %s logged in with SAML", auditEvent.AuthorName)
		case "openid_connect":
			return "User logged in with OpenID Connect", fmt.Sprintf("User %s logged in with OpenID Connect", auditEvent.AuthorName)
		default:
			return "User logged in with unknown method", fmt.Sprintf("User %s logged in with unknown method (%s)", auditEvent.AuthorName, *auditEvent.With)
		}
	}

	if auditEvent.Add != nil {
		return "User event - add", fmt.Sprintf("User %s added %s (target %s)", auditEvent.AuthorName, *auditEvent.Add, auditEvent.EntityPath)
	}

	if auditEvent.CustomMessage != nil {
		return "User event - change", fmt.Sprintf("User %s %s (target %s)", auditEvent.AuthorName, *auditEvent.CustomMessage, auditEvent.EntityPath)
	}

	if auditEvent.Remove != nil {
		return "User event - remove", fmt.Sprintf("User %s removed %s for %s", auditEvent.AuthorName, *auditEvent.Remove, auditEvent.EntityPath)
	}

	return "User event - unknown", fmt.Sprintf("User %s %s (target %s)", auditEvent.AuthorName, *auditEvent.Action, auditEvent.EntityPath)
}

func auditEventToProjectMessageType(auditEvent *AuditEvent) (string, string) {
	if auditEvent.Add != nil {
		return "Project event - add", fmt.Sprintf("User %s added %s %s", auditEvent.AuthorName, *auditEvent.Add, auditEvent.EntityPath)
	}
	if auditEvent.Remove != nil {
		return "Project event - remove", fmt.Sprintf("User %s removed %s %s", auditEvent.AuthorName, *auditEvent.Remove, auditEvent.EntityPath)
	}

	if auditEvent.CustomMessage != nil {
		return "Project event - custom", fmt.Sprintf(
			"User %s changed %s %s: %s",
			auditEvent.AuthorName,
			auditEvent.EntityType,
			auditEvent.EntityPath,
			*auditEvent.CustomMessage)
	}

	if auditEvent.Change != nil {
		return "Project event - change", fmt.Sprintf(
			"User %s changed %s at %s for %s",
			auditEvent.AuthorName,
			*auditEvent.Change,
			auditEvent.EntityPath,
			*auditEvent.TargetDetails)
	}

	return "Project event - unknown", fmt.Sprintf("User %s %s %s", auditEvent.AuthorName, auditEvent.Action, auditEvent.EntityPath)
}

func auditEventToGroupMessageType(auditEvent *AuditEvent) (string, string) {
	if auditEvent.Add != nil {
		return "Group event - add",
			fmt.Sprintf("User %s in group %d added %s %s %s",
				auditEvent.AuthorName,
				auditEvent.EntityID,
				*auditEvent.Add,
				auditEvent.EntityPath,
				*auditEvent.TargetDetails)
	}

	if auditEvent.Remove != nil {
		return "Group event - remove",
			fmt.Sprintf("User %s in group %d removed %s %s %s",
				auditEvent.AuthorName,
				auditEvent.EntityID,
				*auditEvent.Remove,
				auditEvent.EntityPath,
				*auditEvent.TargetDetails)
	}

	if auditEvent.Change != nil {
		return "Group event - change",
			fmt.Sprintf("User %s in group %d change %s %s %s",
				auditEvent.AuthorName,
				auditEvent.EntityID,
				*auditEvent.Change,
				auditEvent.EntityPath,
				*auditEvent.TargetDetails)
	}

	if auditEvent.CustomMessage != nil {
		return "Group event - change",
			fmt.Sprintf(
				"User %s changed %s %s: %s",
				auditEvent.AuthorName,
				auditEvent.EntityType,
				auditEvent.EntityPath,
				*auditEvent.CustomMessage)
	}

	return "Group event - unknown", fmt.Sprintf("User %s %s %s", auditEvent.AuthorName, auditEvent.Action, auditEvent.EntityPath)
}
