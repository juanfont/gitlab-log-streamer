package streamer

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	AuditEventLoginWithTwoFactor = "two-factor"
	AuditEventLoginWithU2F       = "two-factor-via-u2f-device"
	AuditEventLoginWithWebAuthn  = "two-factor-via-webauthn-device"
	AuditEventLoginStandard      = "standard"
)

// forwardBatchSize bounds how many new events are held in memory before
// being forwarded, e.g. on a first start against a large existing log.
const forwardBatchSize = 1000

// readAuditLogFile stores and forwards the audit events appended to the log
// since the previous call.
func (s *GitLabLogStreamer) readAuditLogFile() error {
	newEvents := []*AuditEvent{}

	err := s.auditTailer.readLines(func(line []byte) error {
		if len(line) == 0 {
			return nil
		}

		auditEvent, err := s.parseAuditLogEvent(string(line))
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to parse audit log entry. Content: %s", line)
			return nil
		}

		isNew, err := s.storeAuditEvent(auditEvent)
		if err != nil || !isNew {
			return err
		}

		newEvents = append(newEvents, auditEvent)
		if len(newEvents) >= forwardBatchSize {
			s.forwardNewAuditLogEvents(newEvents)
			newEvents = []*AuditEvent{}
		}

		return nil
	})

	// Forward what was stored even if reading stopped on an error: those
	// events are already marked as seen and would not be forwarded later.
	s.forwardNewAuditLogEvents(newEvents)

	return err
}

func (s *GitLabLogStreamer) forwardNewAuditLogEvents(auditEvents []*AuditEvent) {
	if len(auditEvents) == 0 {
		return
	}

	if s.cfg.AuditLogForwardingEndpoint != "" {
		log.Debug().Msgf("Forwarding %d audit events to HTTP endpoint %s", len(auditEvents), s.cfg.AuditLogForwardingEndpoint)
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
}

// storeAuditEvent persists an audit event that has not been seen before and
// marks it as seen. It reports whether the event was new.
func (s *GitLabLogStreamer) storeAuditEvent(auditEvent *AuditEvent) (bool, error) {
	if s.seenAuditEvents.seen(auditEvent.CorrelationID, auditEvent.Time, uint64(auditEvent.DedupHash)) {
		log.Debug().Msgf("Audit event with correlation ID %s at %s already exists. Skipping", auditEvent.CorrelationID, auditEvent.Time.Format(time.RFC3339))
		return false, nil
	}

	err := s.db.Create(auditEvent).Error
	if err != nil {
		log.Error().Err(err).Msgf("Failed to insert audit event with correlation ID %s", auditEvent.CorrelationID)
		return false, err
	}

	s.seenAuditEvents.add(auditEvent.CorrelationID, auditEvent.Time, uint64(auditEvent.DedupHash))
	auditLogEventsReceived.Inc()
	log.Debug().Msgf("Inserted audit event with correlation ID %s", auditEvent.CorrelationID)

	return true, nil
}

func (s *GitLabLogStreamer) parseAuditLogEvent(line string) (*AuditEvent, error) {
	auditEvent := &AuditEvent{}

	err := json.Unmarshal([]byte(line), auditEvent)
	if err != nil {
		return nil, err
	}
	auditEvent.DedupHash = int64(lineHash([]byte(line)))

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

	action := "unknown action"
	if auditEvent.Action != nil {
		action = *auditEvent.Action
	}

	return "User event - unknown", fmt.Sprintf("User %s %s (target %s)", auditEvent.AuthorName, action, auditEvent.EntityPath)
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
			stringOrEmpty(auditEvent.TargetDetails))
	}

	action := "unknown action"
	if auditEvent.Action != nil {
		action = *auditEvent.Action
	}

	return "Project event - unknown", fmt.Sprintf("User %s %s %s", auditEvent.AuthorName, action, auditEvent.EntityPath)
}

func auditEventToGroupMessageType(auditEvent *AuditEvent) (string, string) {
	if auditEvent.Add != nil {
		return "Group event - add",
			fmt.Sprintf("User %s in group %d added %s %s %s",
				auditEvent.AuthorName,
				auditEvent.EntityID,
				*auditEvent.Add,
				auditEvent.EntityPath,
				stringOrEmpty(auditEvent.TargetDetails))
	}

	if auditEvent.Remove != nil {
		return "Group event - remove",
			fmt.Sprintf("User %s in group %d removed %s %s %s",
				auditEvent.AuthorName,
				auditEvent.EntityID,
				*auditEvent.Remove,
				auditEvent.EntityPath,
				stringOrEmpty(auditEvent.TargetDetails))
	}

	if auditEvent.Change != nil {
		return "Group event - change",
			fmt.Sprintf("User %s in group %d change %s %s %s",
				auditEvent.AuthorName,
				auditEvent.EntityID,
				*auditEvent.Change,
				auditEvent.EntityPath,
				stringOrEmpty(auditEvent.TargetDetails))
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

	action := "unknown action"
	if auditEvent.Action != nil {
		action = *auditEvent.Action
	}

	return "Group event - unknown", fmt.Sprintf("User %s %s %s", auditEvent.AuthorName, action, auditEvent.EntityPath)
}

// stringOrEmpty dereferences an optional field such as target_details, which
// GitLab omits from some audit events.
func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
