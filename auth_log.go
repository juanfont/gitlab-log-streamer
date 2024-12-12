package streamer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

func (s *GitLabLogStreamer) readAuthLogFile() error {
	content, err := os.ReadFile(s.cfg.AuthLogPath)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Split(bufio.ScanLines)

	authEvents := []*AuthEvent{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			log.Warn().Msg("Empty line in auth log")
			continue
		}

		authEvent, err := s.parseAuthEvent(line)
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to parse auth log entry. Content: %s", line)
			continue
		}

		authEvents = append(authEvents, authEvent)
	}

	newEvents, err := s.processNewAuthEvents(authEvents)
	if err != nil {
		return err
	}

	if len(newEvents) == 0 {
		log.Warn().
			Msg("No new auth events to forward, but a full read was requested")
	}

	err = s.forwardNewAuthEvents(newEvents)
	if err != nil {
		return err
	}

	return nil
}

func (s *GitLabLogStreamer) forwardNewAuthEvents(authEvents []*AuthEvent) error {
	if s.cfg.AuditLogForwardingEndpoint != "" {
		log.Info().
			Int("events", len(authEvents)).
			Str("endpoint", s.cfg.AuditLogForwardingEndpoint).
			Msgf("Forwarding auth events to HTTP endpoint")
		err := s.forwardNewAuthEventsHTTP(authEvents)
		if err != nil {
			log.Warn().
				Err(err).
				Msg("Failed to forward auth events to HTTP endpoint")
		}
	}

	if s.cfg.SyslogServerAddr != "" {
		err := s.forwardNewAuthEventsSyslog(authEvents)
		if err != nil {
			log.Warn().
				Err(err).
				Msg("Failed to forward audit events to syslog server")
		}
	}

	return nil
}

func (s *GitLabLogStreamer) processNewAuthEvents(authEvents []*AuthEvent) ([]*AuthEvent, error) {
	newEvents := []*AuthEvent{}

	for _, authEvent := range authEvents {
		// check if the auditEvent correlation ID already exists
		// if it does, we skip it
		// if it doesn't, we insert it

		_, ok := s.latestAuthEvents.Load(fmt.Sprintf("%s,%d", authEvent.CorrelationID, authEvent.Time.UnixNano()))
		if ok {
			log.Debug().Msgf("Auth event with correlation ID %s at %s already exists. Skipping", authEvent.CorrelationID, authEvent.Time.Format(time.RFC3339))
			continue
		}

		err := s.db.Create(authEvent).Error
		if err != nil {
			log.Error().Err(err).Msgf("Failed to insert auth event with correlation ID %s", authEvent.CorrelationID)
			return newEvents, err
		}

		s.latestAuthEvents.Store(fmt.Sprintf("%s,%d", authEvent.CorrelationID, authEvent.Time.UnixNano()), *authEvent)
		newEvents = append(newEvents, authEvent)
		log.Info().Msgf("Inserted auth event with correlation ID %s", authEvent.CorrelationID)
	}

	log.Info().Msgf("Inserted %d new auth events", len(newEvents))

	return newEvents, nil
}

func (s *GitLabLogStreamer) parseAuthEvent(line string) (*AuthEvent, error) {
	authEvent := &AuthEvent{}
	err := json.Unmarshal([]byte(line), authEvent)
	if err != nil {
		return nil, err
	}

	return authEvent, nil
}

func getAuthEventMessageType(event *AuthEvent) string {
	if event.Message != nil {
		return *event.Message
	}

	if event.MetaFeatureCategory != nil {
		return *event.MetaFeatureCategory
	}

	return "unknown"
}
