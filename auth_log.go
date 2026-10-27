package streamer

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/rs/zerolog/log"
)

// readAuthLogFile stores and forwards the auth events appended to the log
// since the previous call.
func (s *GitLabLogStreamer) readAuthLogFile() error {
	newEvents := []*AuthEvent{}

	err := s.authTailer.readLines(func(line []byte) error {
		if len(line) == 0 {
			return nil
		}

		authEvent, err := s.parseAuthEvent(string(line))
		if err != nil {
			log.Warn().Err(err).Msgf("Failed to parse auth log entry. Content: %s", line)
			return nil
		}

		if s.isDroppedAuthEvent(authEvent) {
			authLogEventsDropped.Inc()
			return nil
		}

		isNew, err := s.storeAuthEvent(authEvent)
		if err != nil || !isNew {
			return err
		}

		newEvents = append(newEvents, authEvent)
		if len(newEvents) >= forwardBatchSize {
			s.forwardNewAuthEvents(newEvents)
			newEvents = []*AuthEvent{}
		}

		return nil
	})

	// Forward what was stored even if reading stopped on an error: those
	// events are already marked as seen and would not be forwarded later.
	s.forwardNewAuthEvents(newEvents)

	return err
}

// isDroppedAuthEvent reports whether the event's message is listed in
// filters.auth_log.drop_messages.
func (s *GitLabLogStreamer) isDroppedAuthEvent(authEvent *AuthEvent) bool {
	return authEvent.Message != nil && slices.Contains(s.cfg.AuthLogDropMessages, *authEvent.Message)
}

func (s *GitLabLogStreamer) forwardNewAuthEvents(authEvents []*AuthEvent) {
	if len(authEvents) == 0 {
		return
	}

	if s.cfg.AuditLogForwardingEndpoint != "" {
		log.Debug().
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
}

// storeAuthEvent persists an auth event that has not been seen before and
// marks it as seen. It reports whether the event was new.
func (s *GitLabLogStreamer) storeAuthEvent(authEvent *AuthEvent) (bool, error) {
	if s.seenAuthEvents.seen(authEvent.CorrelationID, authEvent.Time) {
		log.Debug().Msgf("Auth event with correlation ID %s at %s already exists. Skipping", authEvent.CorrelationID, authEvent.Time.Format(time.RFC3339))
		return false, nil
	}

	err := s.db.Create(authEvent).Error
	if err != nil {
		log.Error().Err(err).Msgf("Failed to insert auth event with correlation ID %s", authEvent.CorrelationID)
		return false, err
	}

	s.seenAuthEvents.add(authEvent.CorrelationID, authEvent.Time)
	authLogEventsReceived.Inc()
	log.Debug().Msgf("Inserted auth event with correlation ID %s", authEvent.CorrelationID)

	return true, nil
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
