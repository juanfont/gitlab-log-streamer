package streamer

import (
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

type Config struct {
	AuditLogForwardingEndpoint string
	AuditLogPath               string
	DBpath                     string
}

type AuditLogStreamer struct {
	cfg Config
	db  *gorm.DB
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
