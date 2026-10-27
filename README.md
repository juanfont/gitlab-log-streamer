# GitLab Log Streamer

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

GitLab writes its audit and authentication events to `audit_json.log` and
`auth_json.log` on the GitLab server. Those files stay on the server's disk.
Getting them into a SIEM or an automation pipeline usually means building your
own log shipping.

`gitlab-log-streamer` is a small daemon that runs on the GitLab server and:

1. tails `audit_json.log` and `auth_json.log`, reading only what GitLab
   appends and following log rotation,
2. stores every event in a local SQLite database, so an event is never
   forwarded twice, even across restarts,
3. forwards each new event to one or more destinations:
   - **HTTP**: one JSON `POST` per event, so you can trigger actions much like
     GitLab System Hooks,
   - **Syslog** in [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424)
     format, or
   - **Syslog with LEEF 2.0** payloads, the format IBM QRadar expects.

It is a single static Linux binary with no runtime dependencies (no CGO, no
external SQLite).

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running](#running)
- [Output formats](#output-formats)
- [Behaviour you should know about](#behaviour-you-should-know-about)
- [Observability](#observability)
- [Building from source](#building-from-source)
- [License](#license)

## Requirements

- A Linux GitLab server (Omnibus install) on amd64.
- Read access to the GitLab log directory, which is usually
  `/var/log/gitlab/gitlab-rails/`. Omnibus restricts that directory, so run
  the streamer as `root` or as the `git` user.
- Optional: read access to `/opt/gitlab/version-manifest.txt`. The GitLab
  version found there goes into the LEEF header. Only GitLab EE manifests are
  recognised today.

## Installation

Download the latest binary from the
[releases page](https://github.com/juanfont/gitlab-log-streamer/releases) and
install it on the GitLab server:

```sh
install -m 0755 gitlab-log-streamer_*_linux_amd64 /usr/local/bin/gitlab-log-streamer
gitlab-log-streamer version
```

### systemd

An example unit, saved as `/etc/systemd/system/gitlab-log-streamer.service`:

```ini
[Unit]
Description=GitLab Log Streamer
After=network-online.target gitlab-runsvdir.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/gitlab-log-streamer watch -c /etc/gitlab-log-streamer/config.yaml
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload
systemctl enable --now gitlab-log-streamer
journalctl -u gitlab-log-streamer -f
```

## Configuration

The config file is YAML. The streamer looks for it in this order:

1. the path given with `-c` / `--config`,
2. the path in the `STREAMER_CONFIG` environment variable,
3. `config.yaml` in `/etc/gitlab-log-streamer/`, then
   `$HOME/.gitlab-log-streamer/`, then the current directory.

A complete example (see also [`config.example.yml`](config.example.yml)):

```yaml
---
# Required. SQLite database used for deduplication and history.
db_path: "/var/lib/gitlab-log-streamer/streamer.sqlite"

# Hostname placed in the syslog/LEEF header.
gitlab_hostname: "gitlab.example.com"

# Address of the observability HTTP server (/metrics and /health).
listen_addr: "127.0.0.1:9188"

# Optional: debug, info, warn, error. Defaults to info.
log_level: "info"

sources:
  # Required.
  audit_log_path: "/var/log/gitlab/gitlab-rails/audit_json.log"
  auth_log_path: "/var/log/gitlab/gitlab-rails/auth_json.log"

destinations:
  # Optional. Each new event is POSTed as JSON to these URLs.
  http:
    audit_log_url: "https://hooks.example.com/gitlab/audit"
    auth_log_url: "https://hooks.example.com/gitlab/auth"

    # Optional headers added to every request, e.g. for authentication.
    # Content-Type defaults to application/json and can be overridden here.
    headers:
      Authorization: "Bearer change-me"

  # Optional. Every new event is also sent to this syslog server.
  syslog:
    server_addr: "siem.example.com:514"
    protocol: "udp" # or "tcp"

    # true = LEEF 2.0 (IBM QRadar), false = RFC 5424 structured data.
    use_leef: false

# Optional. How long events are remembered for deduplication. Default: 48h.
dedup_window: "48h"

# Optional. Drop auth events by exact `message` before they are stored,
# counted or forwarded. Empty by default.
filters:
  auth_log:
    drop_messages:
      - "IAM JWT authentication attempt when disabled"
```

| Key | Required | Description |
|---|---|---|
| `db_path` | yes | Path of the SQLite database. The file is created if it does not exist. |
| `sources.audit_log_path` | yes | GitLab `audit_json.log`. |
| `sources.auth_log_path` | yes, in practice | GitLab `auth_json.log`. Startup fails if this file can't be read. |
| `gitlab_hostname` | no | `HOSTNAME` field of syslog and LEEF messages. |
| `listen_addr` | recommended | Listen address of `/metrics` and `/health`. If empty, the server binds `:80`, which fails when not running as root and stops the streamer. |
| `log_level` | no | `debug`, `info`, `warn` or `error` (default `info`). |
| `destinations.http.audit_log_url` | no | Receives audit events. |
| `destinations.http.auth_log_url` | no | Receives auth events. |
| `destinations.http.headers` | no | Map of extra HTTP headers. |
| `destinations.syslog.server_addr` | no | `host:port` of the syslog server. Leave it empty to disable syslog. |
| `destinations.syslog.protocol` | with syslog | `udp` or `tcp`. |
| `destinations.syslog.use_leef` | no | Send LEEF 2.0 instead of RFC 5424. |
| `dedup_window` | no | How long events are remembered for deduplication, as a Go duration (default `48h`). It must be longer than the age of the oldest line in the live log files. See [Deduplication](#behaviour-you-should-know-about). |
| `filters.auth_log.drop_messages` | no | List of auth log `message` values to drop. Matching is exact and case-sensitive. Dropped events are not stored or forwarded, and are counted in `gitlab_log_streamer_auth_log_events_dropped`. Empty by default. |

### Filtering noisy auth events

GitLab 19.4 started logging `IAM JWT authentication attempt when disabled`
on every token-authenticated request (Git over HTTP, registry, API) when IAM
is disabled, which is always the case on self-managed instances. On a busy
instance it can make up the vast majority of `auth_json.log`. If your
consumers don't need it:

```yaml
filters:
  auth_log:
    drop_messages:
      - "IAM JWT authentication attempt when disabled"
```

### Environment overrides

Any key can be overridden with an environment variable. Prefix the key with
`STREAMER_`, upper-case it, and replace dots with underscores:

```sh
STREAMER_DESTINATIONS_HTTP_AUDIT_LOG_URL=https://other.example.com/hook \
  gitlab-log-streamer watch
```

The required keys (`db_path`, `sources.audit_log_path`) are validated before
overrides are applied, so they must be in the config file. The
`destinations.http.headers` map and `filters.auth_log.drop_messages` list can
only be set in the file.

## Running

```sh
gitlab-log-streamer watch            # or: gitlab-log-streamer w
gitlab-log-streamer watch -c ./config.yaml
gitlab-log-streamer version
```

Logs are written to stdout. Colour is used when the terminal supports it, and
setting `NO_COLOR` turns it off. At the default `info` level the streamer
logs startup, rotation and errors only. Per-event and per-write lines are at
`debug`.

## Output formats

The examples below are all generated from this audit event:

```json
{"severity":"INFO","time":"2026-10-27T10:00:00.000Z","correlation_id":"01JB3X","author_id":1,"author_name":"Jane Doe","entity_id":1,"entity_type":"User","with":"standard","entity_path":"jdoe","ip_address":"192.0.2.10","target_id":1,"target_type":"User","target_details":"Jane Doe"}
```

### HTTP

Each event is sent as its own `POST` with a JSON body. The body uses GitLab's
field names. Core fields are always present, possibly empty or `null`.
Optional fields are left out when they are missing from the log line. Fields
the streamer doesn't model are dropped.

```json
{"correlation_id":"01JB3X","severity":"INFO","time":"2026-10-27T10:00:00Z","author_id":1,"author_name":"Jane Doe","entity_id":1,"entity_type":"User","ip_address":"192.0.2.10","with":"standard","target_id":1,"target_type":"User","target_details":"Jane Doe","entity_path":"jdoe", ...}
```

The request has a 10 second timeout. Any non-2xx response is logged as a
failure.

### Syslog (RFC 5424)

The facility is 13 (log audit), and the severity comes from the event's
`severity`. All event fields go into a single `audit_event` structured-data
element. These SD parameter names are the streamer's internal field names
(`AuthorName`, `CorrelationID`, …), not GitLab's JSON names. The
human-readable summary of the event is used as both the MSGID and the message.

```
<110>1 2026-10-27T10:00:00Z gitlab.example.com gitlab 4242 User-logged-in [audit_event AuthorName="Jane Doe" CorrelationID="01JB3X" EntityPath="jdoe" IPAddress="192.0.2.10" With="standard" ...] User Jane Doe logged in
```

### Syslog (LEEF 2.0, for QRadar)

Messages use the same RFC 5424 header, followed by a LEEF 2.0 payload with `^`
as the attribute delimiter. The header carries vendor `GitLab Inc.`, product
`GitLab` and the version from the GitLab version manifest. The event ID is the
summary of the event. Besides the event fields, every message has `msg`
(human-readable message), `sev` and `pid`. Attribute order is not fixed.

```
<110>1 2026-10-27T10:00:00Z gitlab.example.com LEEF:2.0|GitLab Inc.|GitLab|17.5.1|User logged in|^|AuthorName=Jane Doe^CorrelationID=01JB3X^EntityPath=jdoe^IPAddress=192.0.2.10^With=standard^msg=User Jane Doe logged in^sev=INFO^pid=4242^...
```

Each batch of new events is sent over one connection, one message per line.
With TCP this means newline-delimited framing.

## Behaviour you should know about

- **The first run forwards the whole existing log.** On startup the streamer
  reads both log files completely, so every event that isn't in the database
  yet is stored and forwarded. If you don't want your destinations to receive
  the backlog, start it once with no destinations configured, then add them.
- **Incremental reads.** The streamer remembers how far it has read each file
  and reads only appended lines. A line is processed only once it is complete
  (ends in a newline). If storing an event fails, that line is retried on the
  next change.
- **Log rotation.** GitLab (Omnibus) rotates these logs daily with logrotate's
  `copytruncate`: the file is copied to `.1` and truncated in place. The
  streamer detects this because the file shrinks, or because the bytes it last
  read are no longer where it left them, and starts again from the beginning
  of the file. Rename-based rotation (`logrotate_method` other than
  `copytruncate`) is also followed. Lines GitLab writes between logrotate's
  copy and truncate only exist in the rotated file and are not forwarded.
  This is inherent to `copytruncate`.
- **Deduplication.** An event is identified by its correlation ID plus its
  timestamp, because GitLab reuses correlation IDs. On startup the streamer
  reads both files from the beginning. Events stored within the last
  `dedup_window` are skipped, so nothing is forwarded twice across a restart.
  This only works if the live log files hold nothing older than the window.
  With GitLab's daily rotation the default `48h` is enough.
- **Forwarding is best-effort.** A failed forward is logged but not retried.
  The event is still stored in the database. Events produced while a
  destination is down are not sent to it later.
- **Retention.** Auth events are deleted from the database after 60 days.
  Audit events are never deleted.
- **Database files.** The SQLite database runs in WAL mode, so `db_path` has
  two companion files, `-wal` and `-shm`, in the same directory. The
  streamer needs write access to that directory. For a consistent backup
  while it runs, use `sqlite3 <db_path> ".backup <dest>"`.

## Observability

The server on `listen_addr` exposes:

- `GET /health`, which returns `200 OK` while the process is running,
- `GET /metrics` with Prometheus metrics:
  - `gitlab_log_streamer_audit_log_events_received`: new audit events stored
    (counter)
  - `gitlab_log_streamer_auth_log_events_received`: new auth events stored
    (counter)
  - `gitlab_log_streamer_auth_log_events_dropped`: auth events dropped by
    `filters.auth_log.drop_messages` (counter)
  - the standard Go runtime and process metrics.

Bind it to `127.0.0.1` unless your Prometheus scrapes it from another host.

## Building from source

You need Go (see the version in [`go.mod`](go.mod)).

```sh
go build -o gitlab-log-streamer ./cmd/streamer
go test ./...
```

Releases are built by GoReleaser. Pushing a `v*` tag runs
[`.github/workflows/releaser.yml`](.github/workflows/releaser.yml).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
