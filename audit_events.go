package streamer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/influxdata/go-syslog/rfc5424"
	"github.com/juanfont/gitlab-log-streamer/pkg/leef"
	"github.com/rs/zerolog/log"
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

	conn, err := net.Dial(s.cfg.SyslogProtocol, s.cfg.SyslogServerAddr)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to syslog server")
		return err
	}
	defer conn.Close()

	for _, auditEvent := range auditEvents {
		var str string
		if s.cfg.UseLEEF {
			str = s.auditEventToLEEF(auditEvent).String()
		} else {
			syslogMsg := s.auditEventToSyslogMessage(auditEvent)
			str, _ = syslogMsg.String()
		}

		log.Info().Msg(str)

		_, err = conn.Write([]byte(str + "\n"))
		if err != nil {
			log.Error().Err(err).Msg("Failed to send syslog message")
			continue
		}
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

func (s *AuditLogStreamer) auditEventToLEEF(auditEvent *AuditEvent) leef.LEEFMessage {
	syslogHeader := leef.SyslogRFC5424Header{
		Priority:  13*8 + logLevelStringToSyslog(auditEvent.Severity), // facility 13 is "security/authorization"
		Timestamp: auditEvent.Time.Format(time.RFC3339),
		Hostname:  s.cfg.GitlabHostname,
	}

	messageID, message := getAuditEventMessageType(auditEvent)
	fieldsMap := auditEventFieldsToMap(auditEvent)
	fieldsMap["msg"] = message
	fieldsMap["pid"] = fmt.Sprintf("%d", os.Getpid())
	fieldsMap["sev"] = auditEvent.Severity

	msg := leef.LEEFMessage{
		SyslogHeader:    syslogHeader,
		LEEFVersion:     "2.0",
		Vendor:          "GitLab Inc.",
		Product:         "GitLab",
		Version:         s.currentGitlabVersion,
		EventID:         messageID,
		Separator:       "^",
		EventAttributes: fieldsMap,
	}

	return msg
}

func (s *AuditLogStreamer) auditEventToSyslogMessage(auditEvent *AuditEvent) rfc5424.SyslogMessage {
	msg := rfc5424.SyslogMessage{}

	facility := 13 // audit log
	priority := facility*8 + logLevelStringToSyslog(auditEvent.Severity)

	msg.SetPriority(uint8(priority))
	msg.SetVersion(1)

	msg.SetTimestamp(auditEvent.Time.Format(time.RFC3339))
	msg.SetAppname("gitlab")
	msg.SetHostname(s.cfg.GitlabHostname)
	msg.SetProcID(fmt.Sprintf("%d", os.Getpid()))

	fieldsMap := auditEventFieldsToMap(auditEvent)
	for k, v := range fieldsMap {
		msg.SetParameter("audit_event", k, fmt.Sprintf("%v", v))
	}

	messageID, message := getAuditEventMessageType(auditEvent)
	msg.SetMsgID(messageID)
	msg.SetMessage(message)

	return msg
}

func auditEventFieldsToMap(auditEvent *AuditEvent) map[string]string {
	fieldMap := map[string]string{}
	reflectValue := reflect.ValueOf(*auditEvent)
	for i := 0; i < reflectValue.NumField(); i++ {
		fieldName := reflectValue.Type().Field(i).Name
		if fieldName == "" {
			continue
		}

		fieldValue := reflectValue.Field(i).Interface()

		// check if fieldValue is a pointer
		// if it is, we need to dereference it
		if reflectValue.Field(i).Kind() == reflect.Ptr && !reflectValue.Field(i).IsNil() {
			fieldValue = reflectValue.Field(i).Elem().Interface()
		}

		if reflectValue.Field(i).Kind() != reflect.Ptr || !reflectValue.Field(i).IsNil() {
			fieldMap[fieldName] = fmt.Sprintf("%v", fieldValue)
		}
	}

	return fieldMap
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

	return "User event - unknown", fmt.Sprintf("User %s %s (target %s)", auditEvent.AuthorName, auditEvent.Action, auditEvent.EntityPath)
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
