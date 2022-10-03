package streamer

import (
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const (
	GitlabVersionManifestPath = "/opt/gitlab/version-manifest.txt"
)

type Config struct {
	AuditLogForwardingEndpoint string
	GitlabHostname             string
	AuditLogPath               string
	DBpath                     string

	SyslogServerAddr string
	SyslogProtocol   string
	UseLEEF          bool // Use QRadar propietary LEEF format
}

type AuditLogStreamer struct {
	cfg Config
	db  *gorm.DB

	currentGitlabVersion string
}

func NewAuditLogStreamer(config Config) (*AuditLogStreamer, error) {

	// we check if the file exists
	// if not, we return an error
	if _, err := os.Stat(config.AuditLogPath); os.IsNotExist(err) {
		return nil, err
	}

	streamer := &AuditLogStreamer{
		cfg: config,
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

	streamer.loadAuditLogEvents()

	return streamer, nil
}

func (s *AuditLogStreamer) Watch() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal().Caller().Err(err).Msgf("Error creating fsnotify watcher")
	}
	defer watcher.Close()

	log.Info().Caller().Msgf("Watching for changes in %s", s.cfg.AuditLogPath)

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				s.handleEvent(event)
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
		log.Fatal().Caller().Err(err)
	}
	<-done

	return nil
}

func (s *AuditLogStreamer) handleEvent(event fsnotify.Event) {
	switch event.Name {
	case s.cfg.AuditLogPath:
		if event.Op&fsnotify.Write == fsnotify.Write {
			log.Info().Caller().Msgf("Audit log file %s modified", event.Name)
			s.loadAuditLogEvents()
		}
	}
}
