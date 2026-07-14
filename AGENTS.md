# AGENTS.md

Guidance for coding agents (and new contributors) working on this repository.

## What this project is

`gitlab-log-streamer` is a small Go daemon that watches GitLab's
`audit_json.log` and `auth_json.log` files, stores each event in a local
SQLite database (for deduplication and retention), and forwards new events to:

- an HTTP endpoint (JSON POST, one request per event), and/or
- a syslog server, either in RFC5424 format or IBM QRadar's LEEF 2.0 format.

It is designed to run on the GitLab server itself (it reads
`/opt/gitlab/version-manifest.txt` to stamp the GitLab version on LEEF
messages).

## Layout

| Path | Purpose |
|---|---|
| `app.go` | `GitLabLogStreamer` struct, config, fsnotify watch loop, DB preload, hourly cleanup |
| `audit_log.go` | Read/parse/dedup/forward audit events; human-readable message synthesis |
| `auth_log.go` | Same pipeline for auth events |
| `forward.go` | HTTP, syslog (RFC5424) and LEEF forwarding; struct→map via reflection |
| `db.go` | GORM + pure-Go SQLite (glebarez/sqlite), WAL, single connection, AutoMigrate |
| `types_audit_event.go` / `types_auth_events.go` | Event models (GORM + JSON tags) |
| `metrics.go` | Prometheus counters (`gitlab_log_streamer_*`) |
| `version.go` | Reads GitLab version from the omnibus version manifest |
| `cmd/streamer/` | Cobra CLI (`watch` command) + Viper config loading |
| `pkg/leef/` | Minimal LEEF 2.0 message encoder |

The root package is named `streamer` but lives at the repo root
(`github.com/juanfont/gitlab-log-streamer`).

## Build, test, release

```sh
go build ./...          # build everything
go test ./...           # run tests
go run ./cmd/streamer watch -c config.yaml   # run locally
make build              # goreleaser snapshot build (writes to dist/, untracked)
```

Releases are done by pushing a `v*` tag (see `.github/workflows/releaser.yml`
and `.goreleaser.yml`).

## Key design points (understand before changing)

- **Dedup key**: events are keyed by `"<correlation_id>,<unix_nanos>"` in
  in-memory `xsync.MapOf` maps (`latestAuditLogEvents`, `latestAuthEvents`).
  The timestamp is part of the key because GitLab reuses correlation IDs for
  sequential events. On startup the last 30 days of events are preloaded from
  the DB into these maps.
- **Full re-read**: on every fsnotify Write event the *whole* log file is
  re-read and re-parsed; dedup filters out already-seen events. This is
  intentional (simple, survives log rotation) — don't "optimize" it without
  discussion.
- **SQLite constraints**: the pure-Go SQLite driver requires a single
  connection (`SetMaxOpenConns(1)`); keep it that way.
- **Retention**: auth events older than 60 days are deleted hourly
  (`CleanAuthLogEventsPeriod`). Audit events are kept forever.
- **Forwarding is best-effort**: forward errors are logged and swallowed;
  events are persisted regardless. There is no retry/queue.

## Conventions

- Logging via `zerolog` (`github.com/rs/zerolog/log`), usually with
  `.Caller()` on errors.
- Config via Viper; every `streamer.Config` field maps to a YAML key
  (see `cmd/streamer/cli/utils.go` and `config.example.yml`). The config file
  can also be set with `-c/--config` or the `STREAMER_CONFIG` env var.
- Event struct fields that may be absent in the JSON are pointers with
  `omitempty`.
- New event fields: add to the struct in `types_*.go`; GORM AutoMigrate picks
  them up on next start. `forward.go` serializes structs to syslog/LEEF
  key-value pairs via reflection, so new fields are forwarded automatically.

## Gotchas

- `TODO.md` (if present) is intentionally uncommitted scratch — leave it out
  of commits.
- `dist/` is goreleaser output and must not be committed.
- The configured `destinations.http.headers` in the config file are currently
  **not** applied by `forward.go` (known gap, see TODO).
- `pkg/leef` builds attribute strings from a map, so attribute order is
  non-deterministic — tests must parse, not compare exact strings.
