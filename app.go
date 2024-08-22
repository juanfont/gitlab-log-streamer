package streamer

import (
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const (
	GitlabVersionManifestPath = "/opt/gitlab/version-manifest.txt"
	PreloadEventsPeriodDays   = 30

	CleanAuthLogEventsPeriod = 60 * time.Hour * 24 // time to keep the auth events in the DB
)

type Config struct {
	AuditLogForwardingEndpoint string
	AuthLogForwardingEndpoint  string
	GitlabHostname             string
	AuditLogPath               string
	AuthLogPath                string
	DBpath                     string

	SyslogServerAddr string
	SyslogProtocol   string
	UseLEEF          bool // Use QRadar propietary LEEF format
}

type GitLabLogStreamer struct {
	cfg Config
	db  *gorm.DB

	latestAuditLogEvents *xsync.MapOf[string, AuditEvent]
	latestAuthEvents     *xsync.MapOf[string, AuthEvent]

	currentGitlabVersion string
}

func NewGitLabLogStreamer(config Config) (*GitLabLogStreamer, error) {
	// we check if the file exists
	// if not, we return an error
	if _, err := os.Stat(config.AuditLogPath); os.IsNotExist(err) {
		return nil, err
	}

	streamer := &GitLabLogStreamer{
		cfg:                  config,
		latestAuditLogEvents: xsync.NewMapOf[string, AuditEvent](),
		latestAuthEvents:     xsync.NewMapOf[string, AuthEvent](),
	}

	// run updateCurrentGitlabVersion() every 5 mins
	go func() {
		for {
			err := streamer.updateCurrentGitlabVersion()
			if err != nil {
				log.Error().Caller().Err(err).Msgf("Error while updating current Gitlab version")
			}
			time.Sleep(5 * time.Minute)
		}
	}()

	err := streamer.initDB()
	if err != nil {
		return nil, err
	}

	err = streamer.preloadDBRecentData()
	if err != nil {
		return nil, err
	}

	err = streamer.readAuditLogFile()
	if err != nil {
		return nil, err
	}

	err = streamer.readAuthLogFile()
	if err != nil {
		return nil, err
	}

	go streamer.cleanOldEvents()

	return streamer, nil
}

func (s *GitLabLogStreamer) preloadDBRecentData() error {
	// load the audit log events from the last preloadEventsPeriodDays from s.db
	// and insert them into s.latestAuditLogEvents

	auditEvents := []*AuditEvent{}
	err := s.db.Where("time > ?", time.Now().AddDate(0, 0, -PreloadEventsPeriodDays)).Find(&auditEvents).Error
	if err != nil {
		return err
	}

	for _, event := range auditEvents {
		s.latestAuditLogEvents.Store(event.CorrelationID, *event)
	}

	// load the auth log events from the last preloadEventsPeriodDays from s.db
	// and insert them into s.latestAuthEvents
	authEvent := []*AuthEvent{}
	err = s.db.Where("time > ?", time.Now().AddDate(0, 0, -PreloadEventsPeriodDays)).Find(&authEvent).Error
	if err != nil {
		return err
	}

	for _, event := range authEvent {
		s.latestAuthEvents.Store(event.CorrelationID, *event)
	}

	return nil
}

func (s *GitLabLogStreamer) Watch() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal().Caller().Err(err).Msgf("Error creating fsnotify watcher")
	}
	defer watcher.Close()

	log.Info().Caller().
		Str("audit_log_path", s.cfg.AuditLogPath).
		Str("auth_log_path", s.cfg.AuthLogPath).
		Msgf("Watching for changes in the files")

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				s.handleFileEvent(event)
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Warn().Caller().Err(err).Msgf("Error while watching")
			}
		}
	}()

	err = watcher.Add(s.cfg.AuditLogPath)
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("Error adding audit log file to watcher")
	}

	err = watcher.Add(s.cfg.AuthLogPath)
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("Error adding auth log file to watcher")
	}

	<-done

	return nil
}

func (s *GitLabLogStreamer) handleFileEvent(event fsnotify.Event) {
	switch event.Name {
	case s.cfg.AuditLogPath:
		if event.Op&fsnotify.Write == fsnotify.Write {
			log.Info().Caller().Msgf("Audit log file %s modified", event.Name)
			s.readAuditLogFile()
		}

	case s.cfg.AuthLogPath:
		if event.Op&fsnotify.Write == fsnotify.Write {
			log.Info().Caller().Msgf("Auth log file %s modified", event.Name)
			s.readAuthLogFile()
		}
	}
}

func (s *GitLabLogStreamer) cleanOldEvents() {
	// remove events older than CleanAuthLogEventsPeriod from s.db

	for {
		err := s.db.Where("time < ?", time.Now().Add(-CleanAuthLogEventsPeriod)).Delete(&AuthEvent{}).Error
		if err != nil {
			log.Error().Caller().Err(err).Msg("Error while deleting old auth events")
		}
		time.Sleep(1 * time.Hour)
	}
}
