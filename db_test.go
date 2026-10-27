package streamer

import "testing"

// The DSN pragmas must actually reach SQLite. Up to 0.9.2 the DSN used
// mattn-style params that the pure-Go driver silently ignores, so the DB ran
// in rollback-journal mode with synchronous=FULL (an fsync per insert).
func TestOpenDBEnablesWAL(t *testing.T) {
	s := newTestStreamer(t, "", "")

	var journalMode string
	if err := s.db.Raw("PRAGMA journal_mode").Scan(&journalMode).Error; err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want wal", journalMode)
	}

	var synchronous int
	if err := s.db.Raw("PRAGMA synchronous").Scan(&synchronous).Error; err != nil {
		t.Fatal(err)
	}
	if synchronous != 1 {
		t.Errorf("synchronous = %d, want 1 (NORMAL)", synchronous)
	}
}

func TestOpenDBEnablesForeignKeys(t *testing.T) {
	s := newTestStreamer(t, "", "")

	var foreignKeys int
	if err := s.db.Raw("PRAGMA foreign_keys").Scan(&foreignKeys).Error; err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, want 1", foreignKeys)
	}
}

// Existing DBs were created in rollback-journal mode. Opening one must switch
// it to WAL and keep its rows.
func TestOpenDBSwitchesExistingDBToWAL(t *testing.T) {
	s := newTestStreamer(t, "", "")
	sqlDB, _ := s.db.DB()
	if err := s.db.Exec("PRAGMA journal_mode=DELETE").Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(&AuthEvent{CorrelationID: "existing"}).Error; err != nil {
		t.Fatal(err)
	}
	sqlDB.Close()

	reopened := &GitLabLogStreamer{cfg: s.cfg}
	if err := reopened.initDB(); err != nil {
		t.Fatal(err)
	}

	var journalMode string
	reopened.db.Raw("PRAGMA journal_mode").Scan(&journalMode)
	if journalMode != "wal" {
		t.Errorf("journal_mode after reopen = %q, want wal", journalMode)
	}
	var count int64
	if err := reopened.db.Model(&AuthEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected the existing row to survive the switch, got %d rows", count)
	}
}

// The startup preload and the hourly auth cleanup filter on time.
func TestOpenDBIndexesTime(t *testing.T) {
	s := newTestStreamer(t, "", "")

	if !s.db.Migrator().HasIndex(&AuditEvent{}, "Time") {
		t.Error("audit_events.time is not indexed")
	}
	if !s.db.Migrator().HasIndex(&AuthEvent{}, "Time") {
		t.Error("auth_events.time is not indexed")
	}
}
