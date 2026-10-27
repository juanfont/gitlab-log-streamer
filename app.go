package streamer

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const (
	GitlabVersionManifestPath = "/opt/gitlab/version-manifest.txt"

	// DefaultDedupWindow is used when Config.DedupWindow is not set. GitLab
	// rotates its logs daily, so two days covers the live files.
	DefaultDedupWindow = 48 * time.Hour

	CleanAuthLogEventsPeriod = 60 * time.Hour * 24 // time to keep the auth events in the DB

	// pollInterval re-checks the log files even without fsnotify events, as
	// a safety net for missed events (e.g. an inotify queue overflow).
	pollInterval = 30 * time.Second
)

type Config struct {
	ListenAddr                 string
	AuditLogForwardingEndpoint string
	AuthLogForwardingEndpoint  string
	GitlabHostname             string
	AuditLogPath               string
	AuthLogPath                string
	DBpath                     string

	// HTTPHeaders are added to every forwarded HTTP request (e.g. an
	// Authorization header). They override the default Content-Type.
	HTTPHeaders map[string]string

	SyslogServerAddr string
	SyslogProtocol   string
	UseLEEF          bool // Use QRadar propietary LEEF format

	// DedupWindow is how long events are remembered for deduplication:
	// preloaded from the DB at startup and evicted hourly. It must cover
	// the oldest line in the live log files. Defaults to DefaultDedupWindow.
	DedupWindow time.Duration

	// AuthLogDropMessages lists auth log `message` values that are dropped
	// before being stored, counted or forwarded.
	AuthLogDropMessages []string
}

type GitLabLogStreamer struct {
	cfg Config
	db  *gorm.DB

	seenAuditEvents *dedupSet
	seenAuthEvents  *dedupSet

	auditTailer *logTailer
	authTailer  *logTailer

	currentGitlabVersion string
}

// newStreamer builds the in-memory state of a streamer, without opening the
// DB or starting any goroutines.
func newStreamer(config Config) *GitLabLogStreamer {
	return &GitLabLogStreamer{
		cfg:             config,
		seenAuditEvents: newDedupSet(),
		seenAuthEvents:  newDedupSet(),
		auditTailer:     newLogTailer(config.AuditLogPath),
		authTailer:      newLogTailer(config.AuthLogPath),
	}
}

func (s *GitLabLogStreamer) dedupWindow() time.Duration {
	if s.cfg.DedupWindow > 0 {
		return s.cfg.DedupWindow
	}

	return DefaultDedupWindow
}

func NewGitLabLogStreamer(config Config) (*GitLabLogStreamer, error) {
	// we check if the file exists
	// if not, we return an error
	if _, err := os.Stat(config.AuditLogPath); os.IsNotExist(err) {
		return nil, err
	}

	streamer := newStreamer(config)

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
	// Rebuild the dedup sets from the events stored within the dedup window,
	// so the files can be re-read from the start without re-forwarding.
	cutoff := time.Now().Add(-s.dedupWindow())

	if err := preloadDedupSet(s.db.Model(&AuditEvent{}), cutoff, s.seenAuditEvents); err != nil {
		return err
	}

	if err := preloadDedupSet(s.db.Model(&AuthEvent{}), cutoff, s.seenAuthEvents); err != nil {
		return err
	}

	log.Info().
		Int("audit_events", s.seenAuditEvents.size()).
		Int("auth_events", s.seenAuthEvents.size()).
		Dur("window", s.dedupWindow()).
		Msg("Preloaded dedup state from the DB")

	return nil
}

// preloadDedupSet adds the events matched by query that are newer than cutoff
// to set. Only the dedup key columns are read, so no full events are loaded.
// Rows stored before line hashes existed have a NULL or 0 dedup_hash and are
// added as legacy entries (see dedupSet.seen).
func preloadDedupSet(query *gorm.DB, cutoff time.Time, set *dedupSet) error {
	rows, err := query.Select("correlation_id", "time", "dedup_hash").Where("time > ?", cutoff).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var correlationID string
		var eventTime time.Time
		var hash sql.NullInt64
		if err := rows.Scan(&correlationID, &eventTime, &hash); err != nil {
			return err
		}
		set.add(correlationID, eventTime, uint64(hash.Int64))
	}

	return rows.Err()
}

func (s *GitLabLogStreamer) Watch() error {
	router := mux.NewRouter()
	router.Handle("/metrics", promhttp.Handler())
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	go func() {
		if err := http.ListenAndServe(s.cfg.ListenAddr, router); err != nil {
			log.Fatal().Caller().Err(err).Msgf("Observability server failed on %s", s.cfg.ListenAddr)
		}
	}()
	log.Info().Caller().Msgf("Listening observability on %s", s.cfg.ListenAddr)

	watcher, err := s.newLogWatcher()
	if err != nil {
		log.Fatal().Caller().Err(err).Msgf("Error watching the log files")
	}
	defer watcher.Close()

	log.Info().Caller().
		Str("audit_log_path", s.cfg.AuditLogPath).
		Str("auth_log_path", s.cfg.AuthLogPath).
		Msgf("Watching for changes in the files")

	poll := time.NewTicker(pollInterval)
	defer poll.Stop()

	s.runWatchLoop(watcher, poll.C)

	return nil
}

// newLogWatcher watches the directories holding the log files rather than
// the files themselves, so the watch survives rename-based log rotation.
func (s *GitLabLogStreamer) newLogWatcher() (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	dirs := map[string]struct{}{
		filepath.Dir(s.cfg.AuditLogPath): {},
		filepath.Dir(s.cfg.AuthLogPath):  {},
	}
	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			watcher.Close()
			return nil, err
		}
	}

	return watcher, nil
}

// runWatchLoop reads the log files on fsnotify events and on every tick of
// poll, until the watcher is closed. It is the only reader of the files once
// the streamer is running.
func (s *GitLabLogStreamer) runWatchLoop(watcher *fsnotify.Watcher, poll <-chan time.Time) {
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
			// Events may have been lost (e.g. queue overflow): catch up.
			log.Warn().Caller().Err(err).Msgf("Error while watching")
			s.readLogFiles()

		case <-poll:
			s.readLogFiles()
		}
	}
}

func (s *GitLabLogStreamer) readLogFiles() {
	if err := s.readAuditLogFile(); err != nil {
		log.Error().Caller().Err(err).Msg("Error reading audit log file")
	}
	if err := s.readAuthLogFile(); err != nil {
		log.Error().Caller().Err(err).Msg("Error reading auth log file")
	}
}

func (s *GitLabLogStreamer) handleFileEvent(event fsnotify.Event) {
	// Create and Rename matter for rotation; Remove lets the tailer drain
	// the old file. Chmod is ignored.
	if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) &&
		!event.Has(fsnotify.Rename) && !event.Has(fsnotify.Remove) {
		return
	}

	// The watch is on the parent directory, so events for other files in it
	// arrive here too and are ignored.
	switch filepath.Clean(event.Name) {
	case filepath.Clean(s.cfg.AuditLogPath):
		log.Debug().Caller().Str("op", event.Op.String()).Msgf("Audit log file %s changed", event.Name)
		if err := s.readAuditLogFile(); err != nil {
			log.Error().Caller().Err(err).Msg("Error reading audit log file")
		}

	case filepath.Clean(s.cfg.AuthLogPath):
		log.Debug().Caller().Str("op", event.Op.String()).Msgf("Auth log file %s changed", event.Name)
		if err := s.readAuthLogFile(); err != nil {
			log.Error().Caller().Err(err).Msg("Error reading auth log file")
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

		s.evictOldDedupEntries()

		time.Sleep(1 * time.Hour)
	}
}

// evictOldDedupEntries drops entries from the in-memory dedup sets once they
// fall outside the dedup window. Without this the sets grow for the whole
// process lifetime. This is safe as long as the log files no longer contain
// events older than the window (GitLab rotates them daily), which is the same
// assumption preloadDBRecentData relies on.
func (s *GitLabLogStreamer) evictOldDedupEntries() {
	cutoff := time.Now().Add(-s.dedupWindow())

	s.seenAuditEvents.evictBefore(cutoff)
	s.seenAuthEvents.evictBefore(cutoff)
}
