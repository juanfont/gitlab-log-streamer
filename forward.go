package streamer

import (
	"bytes"
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

func (s *AuditLogStreamer) forwardNewAuditLogEventsHTTP(auditEvents []*AuditEvent) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, auditEvent := range auditEvents {
		data, err := json.Marshal(auditEvent)
		if err != nil {
			log.Error().Err(err).Msg("Failed to marshal audit event")
			continue
		}

		_, err = client.Post(s.cfg.AuditLogForwardingEndpoint,
			"application/json",
			bytes.NewReader(data),
		)
		if err != nil {
			continue
		}

		log.Info().Msg("Audit event forwarded via HTTP")

	}

	return nil
}

func (s *AuditLogStreamer) forwardNewAuditLogEventsSyslog(auditEvents []*AuditEvent) error {
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
