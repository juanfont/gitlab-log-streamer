package streamer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/influxdata/go-syslog/rfc5424"
	"github.com/rs/zerolog/log"
	"github.com/sanity-io/litter"
)

const (
	AuditEventLoginWithTwoFactor = "two-factor"
	AuditEventLoginWithU2F       = "two-factor-via-u2f-device"
	AuditEventLoginWithWebAuthn  = "two-factor-via-webauthn-device"
	AuditEventLoginStandard      = "standard"
)

func (s *AuditLogStreamer) loadAuditLogEvents() error {
	content, err := os.ReadFile(s.cfg.AuditLogPath)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Split(bufio.ScanLines)

	auditEvents := []*AuditEvent{}
	for scanner.Scan() {
		line := scanner.Text()
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

	newEvents, err := s.processAuditLogEvents(auditEvents)
	if err != nil {
		return err
	}

	err = s.forwardNewAuditLogEvents(newEvents)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuditLogStreamer) forwardNewAuditLogEvents(auditEvents []*AuditEvent) error {
	// do HTTP POST requests to the configured endpoint for each audit event

	// create HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, auditEvent := range auditEvents {
		// do HTTP POST request
		_, err := client.Post(s.cfg.AuditLogForwardingEndpoint, "application/json", strings.NewReader(auditEvent.OriginalData.String()))
		if err != nil {
			continue
		}
	}

	for _, auditEvent := range auditEvents {
		syslogMsg := s.auditEventToSyslogMessage(auditEvent)
		fmt.Println(syslogMsg.Valid())
	}

	return nil
}

func (s *AuditLogStreamer) processAuditLogEvents(auditEvents []*AuditEvent) ([]*AuditEvent, error) {
	newEvents := []*AuditEvent{}

	for _, auditEvent := range auditEvents {
		// check if the auditEvent correlation ID already exists
		// if it does, we skip it
		// if it doesn't, we insert it

		var count int64
		err := s.db.Model(&AuditEvent{}).Where("correlation_id = ?", auditEvent.CorrelationID).Count(&count).Error
		if err != nil {
			log.Error().Err(err).Msgf("Failed to check if audit event with correlation ID %s already exists", auditEvent.CorrelationID)
			return newEvents, err
		}

		if count > 0 {
			log.Debug().Msgf("Audit event with correlation ID %s already exists. Skipping", auditEvent.CorrelationID)
			continue
		}

		err = s.db.Create(auditEvent).Error
		if err != nil {
			log.Error().Err(err).Msgf("Failed to insert audit event with correlation ID %s", auditEvent.CorrelationID)
			return newEvents, err
		}

		newEvents = append(newEvents, auditEvent)
		log.Info().Msgf("Inserted audit event with correlation ID %s", auditEvent.CorrelationID)
	}

	log.Info().Msgf("Inserted %d new audit events", len(newEvents))

	return newEvents, nil
}

func (s *AuditLogStreamer) parseAuditLogEvent(line string) (*AuditEvent, error) {
	auditEvent := &AuditEvent{}

	err := json.Unmarshal([]byte(line), auditEvent)
	if err != nil {
		return nil, err
	}

	return auditEvent, nil
}

func (*AuditLogStreamer) auditEventToSyslogMessage(auditEvent *AuditEvent) rfc5424.SyslogMessage {
	msg := rfc5424.SyslogMessage{}

	facility := 13 // audit log
	priority := facility*8 + logLevelStringToSyslog(auditEvent.Severity)

	msg.SetPriority(uint8(priority))
	msg.SetVersion(1)

	msg.SetTimestamp(auditEvent.Time.Format(time.RFC3339))
	msg.SetAppname("gitlab")

	textMessage := auditEventToMessage(auditEvent)
	msg.SetMessage(textMessage)

	// iterate throgh the audit event data using reflection
	reflectValue := reflect.ValueOf(*auditEvent)
	for i := 0; i < reflectValue.NumField(); i++ {
		fieldName := reflectValue.Type().Field(i).Name
		fieldValue := reflectValue.Field(i).Interface()

		// check if fieldValue is a pointer
		// if it is, we need to dereference it
		if reflectValue.Field(i).Kind() == reflect.Ptr && !reflectValue.Field(i).IsNil() {
			fieldValue = reflectValue.Field(i).Elem().Interface()
		}

		if reflectValue.Field(i).Kind() != reflect.Ptr || !reflectValue.Field(i).IsNil() {
			msg.SetParameter("audit_event",
				fieldName,
				fmt.Sprintf("%v", fieldValue))
		}
	}

	return msg
}

func logLevelStringToSyslog(level string) int {
	switch strings.ToLower(level) {
	case "debug":
		return 7
	case "info":
		return 6
	case "warn":
		return 4
	case "error":
		return 3
	case "fatal":
		return 2
	case "panic":
		return 1
	default:
		return 6
	}
}

// auditEventToMessage converts an audit event to a human-readable message
func auditEventToMessage(auditEvent *AuditEvent) string {
	if auditEvent.EntityType == "User" {
		return auditEventToUserMessage(auditEvent)
	}

	if auditEvent.EntityType == "Project" {
		return auditEventToProjectMessage(auditEvent)
	}

	if auditEvent.EntityType == "Group" {
		return auditEventToGroupMessage(auditEvent)
	}

	fmt.Printf("%v", auditEvent)

	return "unkown event"
}

func auditEventToUserMessage(auditEvent *AuditEvent) string {
	if auditEvent.With != nil {
		switch *auditEvent.With {
		case AuditEventLoginWithWebAuthn:
			return fmt.Sprintf("User %s logged in with WebAuthn", auditEvent.AuthorName)
		case AuditEventLoginWithU2F:
			return fmt.Sprintf("User %s logged in with U2F", auditEvent.AuthorName)
		case AuditEventLoginWithTwoFactor:
			return fmt.Sprintf("User %s logged in with two-factor authentication", auditEvent.AuthorName)
		case AuditEventLoginStandard:
			return fmt.Sprintf("User %s logged in", auditEvent.AuthorName)
		case "saml":
			return fmt.Sprintf("User %s logged in with SAML", auditEvent.AuthorName)
		default:
			return fmt.Sprintf("User %s logged in with unknown method (%s)", auditEvent.AuthorName, *auditEvent.With)
		}
	}

	if auditEvent.Add != nil {
		return fmt.Sprintf("User %s added %s (target %s)", auditEvent.AuthorName, *auditEvent.Add, auditEvent.EntityPath)
	}

	if auditEvent.CustomMessage != nil {
		return fmt.Sprintf("User %s %s (target %s)", auditEvent.AuthorName, *auditEvent.CustomMessage, auditEvent.EntityPath)
	}

	if auditEvent.Remove != nil {
		return fmt.Sprintf("User %s removed %s for %s", auditEvent.AuthorName, *auditEvent.Remove, auditEvent.EntityPath)
	}

	return "unknown user event"
}

func auditEventToProjectMessage(auditEvent *AuditEvent) string {
	if auditEvent.Add != nil {
		return fmt.Sprintf("User %s added %s %s", auditEvent.AuthorName, *auditEvent.Add, auditEvent.EntityPath)
	}
	if auditEvent.Remove != nil {
		return fmt.Sprintf("User %s removed %s %s", auditEvent.AuthorName, *auditEvent.Remove, auditEvent.EntityPath)
	}

	if auditEvent.CustomMessage != nil {
		return fmt.Sprintf(
			"User %s changed %s %s: %s",
			auditEvent.AuthorName,
			auditEvent.EntityType,
			auditEvent.EntityPath,
			*auditEvent.CustomMessage)
	}

	if auditEvent.Change != nil {
		return fmt.Sprintf(
			"User %s changed %s at %s for %s",
			auditEvent.AuthorName,
			*auditEvent.Change,
			auditEvent.EntityPath,
			*auditEvent.TargetDetails)
	}

	return "unknown project event"
}

func auditEventToGroupMessage(auditEvent *AuditEvent) string {
	if auditEvent.Add != nil {
		return fmt.Sprintf("User %s in group %d added %s %s %s",
			auditEvent.AuthorName,
			auditEvent.EntityID,
			*auditEvent.Add,
			auditEvent.EntityPath,
			*auditEvent.TargetDetails)
	}

	if auditEvent.Remove != nil {
		return fmt.Sprintf("User %s in group %d removed %s %s %s",
			auditEvent.AuthorName,
			auditEvent.EntityID,
			*auditEvent.Remove,
			auditEvent.EntityPath,
			*auditEvent.TargetDetails)
	}

	if auditEvent.Change != nil {
		return fmt.Sprintf("User %s in group %d change %s %s %s",
			auditEvent.AuthorName,
			auditEvent.EntityID,
			*auditEvent.Change,
			auditEvent.EntityPath,
			*auditEvent.TargetDetails)
	}

	if auditEvent.CustomMessage != nil {
		return fmt.Sprintf(
			"User %s changed %s %s: %s",
			auditEvent.AuthorName,
			auditEvent.EntityType,
			auditEvent.EntityPath,
			*auditEvent.CustomMessage)
	}
	litter.Dump(auditEvent)
	fmt.Println(auditEvent.Time)
	os.Exit(0)

	return "unknown group event"
}
