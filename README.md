# Gitlab Log Streamer

[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

Gitlab Log Streamer is a tool designed to overcome the limitations of Gitlab's `audit_log.json` and potentially other logs.

By default, Gitlab writes its audit events to the `audit_log.json` file, which limits their usefulness as they stay in your GItLab server filesystem.

This project parses the log file, stores the events in a SQLite database, and allows forwarding of new log entries using syslog format (RFC5424) or IBM QRadar's proprietary LEEF. It also supports defining an HTTP endpoint for POST requests with the event, enabling triggers and actions similar to Gitlab System hooks.

## Table of Contents

- [Gitlab Log Streamer](#gitlab-log-streamer)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Usage](#usage)

## Installation

Just head to https://github.com/juanfont/gitlab-log-streamer/releases and grab the latest version.

Then place it in your PATH (e.g., `/usr/local/bin`)

## Usage

You need to create a file named `config.yaml` in the same directory as the binary or in `/etc/gitlab-log-streamer`:

```yaml
---
db_path: "streamer.sqlite"
gitlab_hostname: "gitlab.font.eu"

sources:
  audit_log_path: "/var/log/gitlab/gitlab-rails/audit_json.log"

destinations:
  http:
    url: "http://localhost:8080"
    headers:
      Authorization: "Bearer 1234567890"
      Content-Type: "application/json"
  syslog:
    server_addr: "localhost:1489"
    protocol: "udp"

    # Optional. If true, the syslog message will be in LEEF format. Otherwise, syslog in RFC5424 format.
    use_leef: false
```

And then just execute:

```
gitlab-log-streamer watch

```
