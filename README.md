# Gitlab Log Streamer

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Gitlab Log Streamer is a tool designed to overcome the limitations of Gitlab's `audit_log.json` and `auth_log.json`.

By default, Gitlab writes its audit events to the `audit_json.log` file, which limits their usefulness as they stay in your GitLab server filesystem.

This project parses the log files, stores the events in a SQLite database, and forwards new log entries via syslog (RFC5424) or IBM QRadar's proprietary LEEF format. It can also POST each event as JSON to an HTTP endpoint, enabling triggers and actions similar to Gitlab System Hooks.

## Table of Contents

- [Gitlab Log Streamer](#gitlab-log-streamer)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Usage](#usage)
  - [Observability](#observability)
  - [Building from source](#building-from-source)

## Installation

Just head to https://github.com/juanfont/gitlab-log-streamer/releases and grab the latest version.

Then place it in your PATH (e.g., `/usr/local/bin`). The streamer is meant to run on the GitLab server itself, as it reads the log files (and `/opt/gitlab/version-manifest.txt` for LEEF messages) from the local filesystem.

## Configuration

Create a `config.yaml` in `/etc/gitlab-log-streamer`, `~/.gitlab-log-streamer`, or the current directory. You can also point to a specific file with `--config`/`-c` or the `STREAMER_CONFIG` environment variable.

```yaml
---
db_path: "streamer.sqlite"
gitlab_hostname: "gitlab.example.com"

# Address for the observability HTTP server (/metrics and /health)
listen_addr: "127.0.0.1:8080"

# Optional: zerolog level (debug, info, warn, error). Defaults to info.
log_level: "info"

sources:
  audit_log_path: "/var/log/gitlab/gitlab-rails/audit_json.log"
  auth_log_path: "/var/log/gitlab/gitlab-rails/auth_json.log"

destinations:
  # Each new event is POSTed as JSON to these URLs (both optional)
  http:
    audit_log_url: "https://example.com/audit-hook"
    auth_log_url: "https://example.com/auth-hook"

    # Optional headers added to every forwarded request, e.g. to
    # authenticate against the endpoint. Content-Type defaults to
    # application/json and can be overridden here.
    headers:
      Authorization: "Bearer 1234567890"

  # Optional syslog forwarding
  syslog:
    server_addr: "localhost:1489"
    protocol: "udp" # or "tcp"

    # Optional. If true, the syslog message will be in LEEF format
    # (for IBM QRadar). Otherwise, syslog in RFC5424 format.
    use_leef: false
```

`sources.audit_log_path` and `db_path` are required; everything else is optional.

Events are stored in the SQLite database at `db_path` and deduplicated across restarts, so already-forwarded events are not sent twice. Auth events are pruned from the database after 60 days; audit events are kept.

## Usage

```
gitlab-log-streamer watch
```

## Observability

While running, the streamer exposes on `listen_addr`:

- `/health` — liveness check
- `/metrics` — Prometheus metrics (`gitlab_log_streamer_audit_log_events_received`, `gitlab_log_streamer_auth_log_events_received`, plus Go runtime metrics)

## Building from source

```sh
go build -o gitlab-log-streamer ./cmd/streamer
go test ./...
```
