# Changelog

## v0.9.2 (2026-10-27)

Fixes the memory and CPU use that grew out of control with GitLab 19.4.
GitLab 19.4 logs `IAM JWT authentication attempt when disabled` on every
token-authenticated request, which can multiply `auth_json.log` volume many
times over on a busy instance.

### Changed

- **Log files are tailed instead of re-read.** Each file's read offset is
  tracked and only appended lines are parsed. Previously every write
  re-read and re-parsed the whole file, which cost several cores on a busy
  instance.
  - A trailing partial line is held back until it is complete.
  - Log rotation is followed for both logrotate methods: `copytruncate` (the
    GitLab default) and rename/create.
  - On startup both files are still read from the beginning, and already
    stored events are skipped.
- **Deduplication keeps only keys in memory** (correlation ID and timestamp,
  about 100 bytes per event) instead of full events. The startup preload
  reads only those two columns.
- **The deduplication window is now 48 hours**, down from 30 days, and is
  configurable with `dedup_window`. GitLab rotates its logs daily, so the
  live files never hold more than about a day. The 60-day auth event
  retention in the database is unchanged.
- The streamer watches the log directories instead of the files, and
  re-checks both files every 30 s as a safety net.
- Per-event and per-write log lines (`Inserted auth event …`,
  `Auth log file … modified`, forwarded messages) moved from `info` to
  `debug`.
- Batches with no new events no longer open a syslog connection.

### Added

- `filters.auth_log.drop_messages`: auth events whose `message` matches
  exactly are dropped before being stored, counted or forwarded. Empty by
  default.
- Metric `gitlab_log_streamer_auth_log_events_dropped`.
- `dedup_window` is validated at startup. An unparsable or non-positive
  value is a config error.

### Fixed

- **SQLite WAL mode is actually enabled.** The DSN used parameter names that
  the pure-Go driver ignores, so the database always ran in rollback-journal
  mode with `synchronous=FULL`, one fsync per stored event. It now runs with
  WAL and `synchronous=NORMAL`, which makes inserts well over an order of
  magnitude faster.
- Events stored just before a database error are still forwarded. They
  used to be stored but never sent.

### Upgrading

No config changes are required. Forwarding destinations, payloads and
existing metric names are unchanged.

On first start the existing database is switched to WAL. Two files appear
next to it, `<db_path>-wal` and `<db_path>-shm`, so the streamer needs write
access to the database's directory (not just the file). If you back the
database up while the streamer runs, use `sqlite3 <db_path> ".backup <dest>"`
or copy all three files. Copying only the main file may miss recent events. To stop forwarding the IAM noise, add:

```yaml
filters:
  auth_log:
    drop_messages:
      - "IAM JWT authentication attempt when disabled"
```
