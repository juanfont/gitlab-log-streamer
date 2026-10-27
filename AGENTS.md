# AGENTS.md

Guidance for coding agents and new contributors. User-facing documentation
is in `README.md`. Keep both files in sync when behaviour or config changes.

## What this project is

`gitlab-log-streamer` is a small Go daemon that runs **on the GitLab server**.
It tails GitLab's `audit_json.log` and `auth_json.log`, stores each event in
a local SQLite database (used for deduplication and history), and forwards new
events to:

- an HTTP endpoint (one JSON POST per event), and/or
- a syslog server, as RFC 5424 or as IBM QRadar's LEEF 2.0.

It reads `/opt/gitlab/version-manifest.txt` to put the GitLab version in LEEF
headers.

## Commands

```sh
go build ./...                                 # build everything
go vet ./...                                   # CI runs this
go test ./...                                  # CI runs this
go run ./cmd/streamer watch -c config.yaml     # run locally
```

CI (`.github/workflows/test.yml`) runs vet, test and build on pushes to `main`
and on PRs. Releases: push a `v*` tag, and `.github/workflows/releaser.yml`
runs GoReleaser (`.goreleaser.yml`). The release build is linux/amd64 only,
with `CGO_ENABLED=0`, and stamps `cli.Version` via ldflags.

`Makefile` and `compile_and_deploy.sh` are the maintainer's **local, gitignored**
files. CI doesn't have them, so don't rely on them or add to them.

## Layout

| Path | Purpose |
|---|---|
| `app.go` | `Config`, `GitLabLogStreamer`, startup (`NewGitLabLogStreamer`), directory watch + poll loop, DB preload, hourly cleanup + dedup eviction |
| `tail.go` | `logTailer`: incremental line reader, handles partial lines and both logrotate methods |
| `dedup.go` | `dedupSet`: key-only set of already-stored events |
| `audit_log.go` | Audit pipeline: tail → parse → dedup/insert → forward in batches. Also builds the human-readable message (`getAuditEventMessageType`) |
| `auth_log.go` | The same pipeline for auth events, plus the `drop_messages` filter |
| `forward.go` | HTTP POST, syslog RFC 5424, LEEF building; struct→map via reflection; MSGID sanitising |
| `db.go` | GORM + pure-Go SQLite (`glebarez/sqlite`), WAL + `synchronous=NORMAL`, single connection, AutoMigrate |
| `types_audit_event.go`, `types_auth_events.go` | Event models (GORM + JSON tags) |
| `metrics.go` | Prometheus counters `gitlab_log_streamer_*` |
| `version.go` | Parses the GitLab version from the Omnibus version manifest |
| `cmd/streamer/` | `main` (zerolog console setup) and `cli/` (Cobra commands `watch`, `version`, plus Viper config) |
| `pkg/leef/` | Minimal LEEF 2.0 encoder |

The root package is named `streamer` but lives at the repo root
(`github.com/juanfont/gitlab-log-streamer`).

## Data flow

```
startup: initDB → preloadDBRecentData (dedup_window of keys → dedup sets)
         → readAuditLogFile → readAuthLogFile (both from offset 0)
         → go cleanOldEvents
Watch(): start /metrics + /health server → fsnotify on the log *directories*
         runWatchLoop: event for our path (Write/Create/Rename/Remove),
                       watcher error, or 30 s poll → read<Kind>LogFile()

read<Kind>LogFile:
  logTailer.readLines (only complete lines appended since last call)
  → json.Unmarshal → [auth: drop_messages filter]
  → store<Kind>Event: skip if in dedup set, else db.Create + add to set
  → forwardNew<Kind>Events every 1000 new events and at the end:
    HTTP (if URL set) and syslog (if server_addr set)
```

## Key design points (understand before changing)

- **Tailing, not re-reading.** Up to 0.9.1 every fsnotify Write re-read and
  re-parsed the whole file, and the dedup maps held full events for 30 days.
  With GitLab 19.4's IAM message flooding `auth_json.log`, that grew to many
  cores and many GB on busy instances. `logTailer`
  keeps an offset per file and only reads appended bytes. Its invariants:
  - `offset` only moves past a line after the callback accepted it. Partial
    lines and lines whose store failed are re-read on the next call.
  - **copytruncate is the GitLab Omnibus default** (daily, `compress`, no
    `delaycompress`).
    The file keeps its inode. Truncation is detected by `size < offset`
    **or** by the 256-byte anchor before `offset` no longer matching. The
    anchor check matters: the kernel coalesces the truncate and the following
    writes into one inotify event, so the file can regrow past `offset`
    before we look. Tests cover both.
  - Rename rotation: the old file is drained through the open fd, then the
    new path is read from 0.
  - After any reset the file is read from 0 and the dedup set absorbs the
    overlap.
  - No line-length limit (`ReadBytes`, not `bufio.Scanner`, whose 64 KB
    default would stop at a long line).
- **Watch directories, not files.** A file watch follows the inode and is
  lost on rename rotation. The directory watch also sees every other GitLab
  log, so `handleFileEvent` filters by cleaned path. Watcher errors (e.g.
  inotify queue overflow) and a 30 s poll trigger a read of both files as a
  safety net.
- **Dedup** (`dedupSet`) stores only `{correlation_id, unix_nanos}` keys,
  about 100 B each. Never store event data in it. The timestamp is part of
  the key because GitLab reuses correlation IDs within a request. Preload
  selects only those two columns. The window (`dedup_window`, default 48h)
  must cover the oldest line in the live files. Dedup now only matters after
  a restart or a truncation reset, since both re-read from 0.
- **First start forwards the whole backlog.** The startup read forwards every
  event in the log that isn't in the DB yet. This is documented in the README.
- **SQLite**: the pure-Go driver needs `SetMaxOpenConns(1)`. Keep it.
  Pragmas only take effect as `_pragma=name(value)` DSN params. The
  mattn-style `_journal_mode=WAL` is silently ignored, which is how up to
  0.9.1 the DB ran without WAL at ~250 inserts/s instead of ~12k/s.
  `db_test.go` asserts the effective pragmas.
- **Retention**: auth events older than 60 days are deleted hourly
  (`CleanAuthLogEventsPeriod`). Audit events are kept forever on purpose. The
  DB retention is independent of `dedup_window`, so don't couple them. In the
  same hourly loop, dedup entries older than `dedup_window` are evicted.
- **Forwarding is best-effort**: errors are logged and swallowed, and events
  are persisted anyway. There is no retry or queue. A bad event must not stop
  the batch. Empty batches are skipped, so no syslog dial happens with
  nothing to send.
- **Syslog** opens one `net.Dial` per batch and writes newline-terminated
  messages. Facility is 13; severity comes from `logLevelStringToSyslog`.
- **Log volume**: anything per event or per write logs at Debug. At Info a
  busy instance used to produce ~1,000 journal lines a minute.

## Config

- Viper. Every `streamer.Config` field is mapped from a YAML key in
  `cmd/streamer/cli/utils.go` (`getStreamerConfig`). When you add a config
  field, update `utils.go`, `config.example.yml`, the README config table, and
  `utils_test.go`. Validate values in `loadViperConfig` where Viper would
  silently return a zero value (as for `dedup_window`).
- Config file resolution: `-c/--config`, then `STREAMER_CONFIG`, then
  `config.yaml` in `/etc/gitlab-log-streamer`, `$HOME/.gitlab-log-streamer`
  and `.`.
- Env overrides (`STREAMER_` + key with `.`→`_`) are enabled in `initConfig`
  **after** `loadViperConfig` has validated the required keys
  (`sources.audit_log_path`, `db_path`). So required keys can't come from env
  alone.
- Viper lowercases map keys, so `destinations.http.headers` reaches
  `Config.HTTPHeaders` lowercased. This is harmless because `http.Header.Set`
  canonicalises the names.
- The `version` subcommand skips config loading (`root.go` `init`).

## Event models

- Fields that may be missing from GitLab's JSON are pointers, usually with
  `omitempty`.
- To add a field, add it to the struct in `types_*.go`. GORM AutoMigrate adds
  the column on the next start. `forward.go` builds the syslog/LEEF key-value
  pairs from the struct by reflection, so the new field is forwarded
  automatically, **under its Go field name** (e.g. `AuthorName`, not
  `author_name`). The HTTP payload uses the JSON tags.
- Reflection also emits `ID` (DB primary key) and `OriginalData` (a
  `datatypes.JSON` column that is never populated today). Remember this
  before changing what goes on the wire.
- Message/event-ID synthesis: `getAuditEventMessageType` returns
  `(eventID, message)` based on `EntityType` (User/Project/Group) and on which
  of `With/Add/Remove/Change/CustomMessage/Action` is set.
  `getAuthEventMessageType` uses `Message`, then `MetaFeatureCategory`. The
  RFC 5424 MSGID must go through `toSyslogMsgID`, otherwise go-syslog
  silently drops it.

## Testing

- Use `newTestStreamer(t, auditLines, authLines)` in `streamer_test.go`. It
  builds a streamer (via `newStreamer`) with a temp SQLite DB and temp log
  files, without the background goroutines and the version lookup that
  `NewGitLabLogStreamer` runs. Don't call `NewGitLabLogStreamer` in tests.
  Related helpers: `restartTestStreamer` (same DB and files, dedup preloaded),
  `authLine` / `auditLine` (recent-dated JSON lines), `appendToFile`,
  `forwardAllTo` (HTTP capture), and `counterValue` (reads a Prometheus
  counter without adding `testutil`'s dependencies).
- Tail and rotation behaviour: `tail_test.go` (unit) and `watch_test.go`
  (real fsnotify watcher via `newLogWatcher` + `runWatchLoop`, with a nil or
  manual poll channel).
- `TestDedupSetMemoryShape` asserts 500k dedup entries stay under 150 MB.
  It is skipped with `-short`.
- Use `captureForwardTarget` in `forward_test.go` (an `httptest` server that
  records requests) for HTTP forwarding tests.
- CLI tests (`cmd/streamer/cli/utils_test.go`) use the `writeConfig` helper,
  which calls `viper.Reset()` before and after each test. Viper is global
  state.
- `pkg/leef` builds attributes from a map, so their order is random. Parse
  the output in tests instead of comparing exact strings.
- Prometheus counters are package globals registered by `promauto`. Don't
  re-register them in tests.

## Conventions

- Logging: `zerolog` (`github.com/rs/zerolog/log`). Add `.Caller()` on errors
  in `app.go`-level code. Prefer structured fields (`.Str`, `.Int`, `.Err`)
  in new code.
- Keep the audit and auth code paths symmetric. A fix in one usually belongs
  in the other too.
- Don't add CGO dependencies. The release binary is static.

## Known issues (delete each entry when it's fixed)

- `forwardNewAuthEvents` (`auth_log.go`) checks and logs
  `AuditLogForwardingEndpoint` but posts to `AuthLogForwardingEndpoint`.
- The group add/remove/change messages and the project "change" message
  dereference `TargetDetails` without a nil check, so an event without
  `target_details` panics.
- The audit dedup key collides for distinct events in the same request and
  millisecond. Only the first is stored and forwarded. GitLab's own `id` field
  on audit lines is unique and would make a correct key. That isn't modelled
  yet and needs a DB column plus a preload fallback for old rows.
- `NewGitLabLogStreamer` checks only that the audit log exists, and
  `auth_log_path` isn't validated as required.
- `getCurrentGitlabVersion` only recognises `gitlab-ee` manifests, so CE
  installs log an error every 5 minutes.
- An empty `listen_addr` makes `http.ListenAndServe` bind `:80`.

## Gotchas

- `TODO.md` is the maintainer's uncommitted scratch (gitignored). Leave it out
  of commits.
- `dist/` is GoReleaser output and must not be committed.
- Don't commit a real `config.yaml`. It is gitignored because it may contain
  auth headers.
