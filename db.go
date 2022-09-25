package streamer

import (
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func (s *AuditLogStreamer) initDB() error {
	db, err := s.openDB()
	if err != nil {
		return err
	}

	s.db = db
	return nil
}

func (s *AuditLogStreamer) openDB() (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	gormLogger := logger.Default.LogMode(logger.Silent)

	db, err = gorm.Open(
		sqlite.Open(s.cfg.DBpath+"?_synchronous=1&_journal_mode=WAL"),
		&gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   gormLogger,
		},
	)

	if err != nil {
		return nil, err
	}

	db.Exec("PRAGMA foreign_keys=ON")

	// The pure Go SQLite library does not handle locking in
	// the same way as the C based one and we cant use the gorm
	// connection pool as of 2022/02/23.
	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxIdleTime(time.Hour)

	err = db.AutoMigrate(&AuditEvent{})
	if err != nil {
		return nil, err
	}

	return db, nil
}
