package streamer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/puzpuzpuz/xsync/v3"
)

// newTestStreamer builds a streamer with a temporary SQLite DB and log files,
// without the goroutines and version lookups of NewGitLabLogStreamer.
func newTestStreamer(t *testing.T, auditLines, authLines string) *GitLabLogStreamer {
	t.Helper()

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit_json.log")
	authPath := filepath.Join(dir, "auth_json.log")

	if err := os.WriteFile(auditPath, []byte(auditLines), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authPath, []byte(authLines), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &GitLabLogStreamer{
		cfg: Config{
			DBpath:       filepath.Join(dir, "streamer.sqlite"),
			AuditLogPath: auditPath,
			AuthLogPath:  authPath,
		},
		latestAuditLogEvents: xsync.NewMapOf[string, AuditEvent](),
		latestAuthEvents:     xsync.NewMapOf[string, AuthEvent](),
	}

	if err := s.initDB(); err != nil {
		t.Fatalf("initDB() error = %v", err)
	}

	return s
}

func TestReadAuditLogFileInsertsAndDeduplicates(t *testing.T) {
	s := newTestStreamer(t, sampleAuditLoginLine+"\n", "")

	if err := s.readAuditLogFile(); err != nil {
		t.Fatalf("readAuditLogFile() error = %v", err)
	}

	var count int64
	if err := s.db.Model(&AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 audit event in DB, got %d", count)
	}

	// A second full read of the same file must not insert duplicates.
	if err := s.readAuditLogFile(); err != nil {
		t.Fatalf("second readAuditLogFile() error = %v", err)
	}
	if err := s.db.Model(&AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 audit event after re-read, got %d", count)
	}
}

func TestReadAuthLogFileInsertsAndDeduplicates(t *testing.T) {
	s := newTestStreamer(t, "", sampleAuthLine+"\n")

	for i := range 2 {
		if err := s.readAuthLogFile(); err != nil {
			t.Fatalf("readAuthLogFile() run %d error = %v", i+1, err)
		}
	}

	var count int64
	if err := s.db.Model(&AuthEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 auth event after two reads, got %d", count)
	}
}

func TestProcessNewAuditLogEventsSameCorrelationIDDifferentTime(t *testing.T) {
	s := newTestStreamer(t, "", "")

	first, err := s.parseAuditLogEvent(sampleAuditLoginLine)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.parseAuditLogEvent(sampleAuditLoginLine)
	if err != nil {
		t.Fatal(err)
	}
	// Same correlation ID, but a later timestamp: must be treated as new.
	second.Time = second.Time.Add(1)

	newEvents, err := s.processNewAuditLogEvents([]*AuditEvent{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if len(newEvents) != 2 {
		t.Fatalf("expected 2 new events (dedup key includes nanos), got %d", len(newEvents))
	}
}

func TestPreloadDBRecentData(t *testing.T) {
	s := newTestStreamer(t, sampleAuditLoginLine+"\n", sampleAuthLine+"\n")

	if err := s.readAuditLogFile(); err != nil {
		t.Fatal(err)
	}
	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}

	// A fresh streamer over the same DB should rebuild the dedup maps...
	fresh := &GitLabLogStreamer{
		cfg:                  s.cfg,
		latestAuditLogEvents: xsync.NewMapOf[string, AuditEvent](),
		latestAuthEvents:     xsync.NewMapOf[string, AuthEvent](),
	}
	if err := fresh.initDB(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.preloadDBRecentData(); err != nil {
		t.Fatalf("preloadDBRecentData() error = %v", err)
	}

	// Note: the sample events are dated 2024, outside the 30-day preload
	// window, so they must NOT be preloaded. Re-reading the files with an
	// empty map would re-insert them, which documents that the preload
	// window and dedup work on event time, not insertion time.
	if fresh.latestAuditLogEvents.Size() != 0 {
		t.Errorf("expected no preloaded audit events (samples are older than 30 days), got %d",
			fresh.latestAuditLogEvents.Size())
	}
	if fresh.latestAuthEvents.Size() != 0 {
		t.Errorf("expected no preloaded auth events (samples are older than 30 days), got %d",
			fresh.latestAuthEvents.Size())
	}
}
