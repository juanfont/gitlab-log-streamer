package streamer

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const iamDisabledMessage = "IAM JWT authentication attempt when disabled"

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

	s := newStreamer(Config{
		DBpath:       filepath.Join(dir, "streamer.sqlite"),
		AuditLogPath: auditPath,
		AuthLogPath:  authPath,
	})

	if err := s.initDB(); err != nil {
		t.Fatalf("initDB() error = %v", err)
	}

	return s
}

// restartTestStreamer simulates a process restart: a new streamer over the
// same DB and log files, with the dedup sets rebuilt from the DB.
func restartTestStreamer(t *testing.T, s *GitLabLogStreamer) *GitLabLogStreamer {
	t.Helper()

	fresh := newStreamer(s.cfg)
	if err := fresh.initDB(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.preloadDBRecentData(); err != nil {
		t.Fatalf("preloadDBRecentData() error = %v", err)
	}

	return fresh
}

func authLine(correlationID string, ts time.Time, message string) string {
	return fmt.Sprintf(`{"severity":"INFO","time":%q,"correlation_id":%q,"message":%q,"meta.feature_category":"system_access"}`,
		ts.UTC().Format("2006-01-02T15:04:05.000Z"), correlationID, message)
}

func auditLine(correlationID string, ts time.Time) string {
	return fmt.Sprintf(`{"severity":"INFO","time":%q,"correlation_id":%q,"author_id":1,"author_name":"juan","entity_id":1,"entity_type":"User","with":"standard","entity_path":"juan"}`,
		ts.UTC().Format("2006-01-02T15:04:05.000Z"), correlationID)
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()

	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}

	return m.GetCounter().GetValue()
}

func countRows(t *testing.T, s *GitLabLogStreamer, model any) int64 {
	t.Helper()

	var count int64
	if err := s.db.Model(model).Count(&count).Error; err != nil {
		t.Fatal(err)
	}

	return count
}

// forwardAllTo points both HTTP destinations at a capture server.
func forwardAllTo(t *testing.T, s *GitLabLogStreamer) *[][]byte {
	t.Helper()

	srv, _, bodies := captureForwardTarget(t, http.StatusOK)
	s.cfg.AuditLogForwardingEndpoint = srv.URL
	s.cfg.AuthLogForwardingEndpoint = srv.URL

	return bodies
}

func TestReadAuditLogFileInsertsAndDeduplicates(t *testing.T) {
	s := newTestStreamer(t, sampleAuditLoginLine+"\n", "")

	if err := s.readAuditLogFile(); err != nil {
		t.Fatalf("readAuditLogFile() error = %v", err)
	}
	if count := countRows(t, s, &AuditEvent{}); count != 1 {
		t.Fatalf("expected 1 audit event in DB, got %d", count)
	}

	if err := s.readAuditLogFile(); err != nil {
		t.Fatalf("second readAuditLogFile() error = %v", err)
	}
	if count := countRows(t, s, &AuditEvent{}); count != 1 {
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

	if count := countRows(t, s, &AuthEvent{}); count != 1 {
		t.Fatalf("expected 1 auth event after two reads, got %d", count)
	}
}

func TestReadAuthLogFileForwardsOnlyAppendedEvents(t *testing.T) {
	now := time.Now()
	s := newTestStreamer(t, "", authLine("A", now, "first")+"\n")
	bodies := forwardAllTo(t, s)

	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}
	appendToFile(t, s.cfg.AuthLogPath, authLine("B", now, "second")+"\n")
	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}

	if len(*bodies) != 2 {
		t.Fatalf("expected 2 forwarded events, got %d", len(*bodies))
	}
	if count := countRows(t, s, &AuthEvent{}); count != 2 {
		t.Fatalf("expected 2 auth events in DB, got %d", count)
	}
}

func TestReadAuthLogFileAcrossPartialLine(t *testing.T) {
	line := authLine("A", time.Now(), "split across writes")
	s := newTestStreamer(t, "", line[:20])
	bodies := forwardAllTo(t, s)

	// Half a JSON line must not be parsed, stored or forwarded...
	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}
	if count := countRows(t, s, &AuthEvent{}); count != 0 {
		t.Fatalf("partial line must not be stored, got %d rows", count)
	}

	// ...and must be picked up whole once the rest is written.
	appendToFile(t, s.cfg.AuthLogPath, line[20:]+"\n")
	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}
	if count := countRows(t, s, &AuthEvent{}); count != 1 {
		t.Fatalf("expected the completed line to be stored once, got %d rows", count)
	}
	if len(*bodies) != 1 {
		t.Fatalf("expected 1 forwarded event, got %d", len(*bodies))
	}
}

func TestRestartDoesNotReforwardEventsWithinWindow(t *testing.T) {
	now := time.Now()
	s := newTestStreamer(t,
		auditLine("audit-1", now.Add(-time.Hour))+"\n",
		authLine("auth-1", now.Add(-time.Hour), "Successful login")+"\n"+
			authLine("auth-1", now.Add(-time.Hour+time.Millisecond), "Successful login")+"\n",
	)
	if err := s.readAuditLogFile(); err != nil {
		t.Fatal(err)
	}
	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}

	// After a restart the files are read again from offset 0.
	fresh := restartTestStreamer(t, s)
	bodies := forwardAllTo(t, fresh)
	if err := fresh.readAuditLogFile(); err != nil {
		t.Fatal(err)
	}
	if err := fresh.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}

	if len(*bodies) != 0 {
		t.Fatalf("expected nothing re-forwarded after restart, got %d events", len(*bodies))
	}
	if count := countRows(t, fresh, &AuditEvent{}); count != 1 {
		t.Errorf("expected 1 audit event in DB, got %d", count)
	}
	if count := countRows(t, fresh, &AuthEvent{}); count != 2 {
		t.Errorf("expected 2 auth events in DB, got %d", count)
	}

	// A genuinely new event after the restart is still forwarded.
	appendToFile(t, fresh.cfg.AuthLogPath, authLine("auth-2", now, "Successful login")+"\n")
	if err := fresh.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}
	if len(*bodies) != 1 {
		t.Fatalf("expected the new event to be forwarded, got %d events", len(*bodies))
	}
}

func TestPreloadUsesConfiguredDedupWindow(t *testing.T) {
	now := time.Now()
	s := newTestStreamer(t, "", authLine("inside", now.Add(-time.Hour), "m")+"\n"+
		authLine("outside", now.Add(-3*time.Hour), "m")+"\n")
	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}

	s.cfg.DedupWindow = 2 * time.Hour
	fresh := restartTestStreamer(t, s)

	if fresh.seenAuthEvents.size() != 1 {
		t.Fatalf("expected 1 preloaded auth event inside a 2h window, got %d", fresh.seenAuthEvents.size())
	}
	if !fresh.seenAuthEvents.seen("inside", mustParseAuthLine(t, s, "inside").Time) {
		t.Error("event inside the window should have been preloaded")
	}
}

func mustParseAuthLine(t *testing.T, s *GitLabLogStreamer, correlationID string) AuthEvent {
	t.Helper()

	var event AuthEvent
	if err := s.db.Where("correlation_id = ?", correlationID).First(&event).Error; err != nil {
		t.Fatal(err)
	}

	return event
}

func TestDedupWindowDefaultsToTwoDays(t *testing.T) {
	s := newStreamer(Config{})

	if got := s.dedupWindow(); got != 48*time.Hour {
		t.Fatalf("dedupWindow() = %v, want 48h", got)
	}
}

func TestEvictOldDedupEntriesUsesDedupWindow(t *testing.T) {
	s := newTestStreamer(t, "", "")
	s.cfg.DedupWindow = 2 * time.Hour
	now := time.Now()

	s.seenAuditEvents.add("recent", now.Add(-time.Hour))
	s.seenAuditEvents.add("old", now.Add(-3*time.Hour))
	s.seenAuthEvents.add("recent", now.Add(-time.Hour))
	s.seenAuthEvents.add("old", now.Add(-3*time.Hour))

	s.evictOldDedupEntries()

	if s.seenAuditEvents.seen("old", now.Add(-3*time.Hour)) || s.seenAuthEvents.seen("old", now.Add(-3*time.Hour)) {
		t.Error("entries older than the dedup window should have been evicted")
	}
	if !s.seenAuditEvents.seen("recent", now.Add(-time.Hour)) || !s.seenAuthEvents.seen("recent", now.Add(-time.Hour)) {
		t.Error("entries inside the dedup window should have been kept")
	}
}

func TestAuthMessageFilterDropsEvents(t *testing.T) {
	now := time.Now()
	s := newTestStreamer(t, "",
		authLine("iam-1", now, iamDisabledMessage)+"\n"+
			authLine("login-1", now, "Successful login")+"\n"+
			authLine("iam-2", now, iamDisabledMessage)+"\n")
	s.cfg.AuthLogDropMessages = []string{iamDisabledMessage}
	bodies := forwardAllTo(t, s)

	droppedBefore := counterValue(t, authLogEventsDropped)
	receivedBefore := counterValue(t, authLogEventsReceived)

	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}

	if len(*bodies) != 1 {
		t.Errorf("expected only the non-filtered event to be forwarded, got %d", len(*bodies))
	}
	if count := countRows(t, s, &AuthEvent{}); count != 1 {
		t.Errorf("expected only the non-filtered event to be stored, got %d", count)
	}
	if s.seenAuthEvents.size() != 1 {
		t.Errorf("dropped events must not enter the dedup set, got %d entries", s.seenAuthEvents.size())
	}
	if got := counterValue(t, authLogEventsDropped) - droppedBefore; got != 2 {
		t.Errorf("dropped counter increased by %v, want 2", got)
	}
	if got := counterValue(t, authLogEventsReceived) - receivedBefore; got != 1 {
		t.Errorf("received counter increased by %v, want 1", got)
	}
}

func TestAuthMessageFilterEmptyByDefault(t *testing.T) {
	s := newTestStreamer(t, "", authLine("iam-1", time.Now(), iamDisabledMessage)+"\n")

	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}

	if count := countRows(t, s, &AuthEvent{}); count != 1 {
		t.Fatalf("with no filter configured the event must be stored, got %d", count)
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

	fresh := restartTestStreamer(t, s)

	// The sample events are dated 2024, outside the dedup window, so they
	// must NOT be preloaded: the window works on event time, not insertion
	// time.
	if fresh.seenAuditEvents.size() != 0 {
		t.Errorf("expected no preloaded audit events, got %d", fresh.seenAuditEvents.size())
	}
	if fresh.seenAuthEvents.size() != 0 {
		t.Errorf("expected no preloaded auth events, got %d", fresh.seenAuthEvents.size())
	}
}
