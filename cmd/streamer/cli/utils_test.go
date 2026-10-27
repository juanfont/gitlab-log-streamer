package cli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// writeConfig writes a config.yaml into a temp dir and loads it into viper.
func writeConfig(t *testing.T, content string) {
	t.Helper()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// viper keeps global state; make sure each test starts clean.
	viper.Reset()
	t.Cleanup(viper.Reset)

	if err := loadViperConfig(dir, false); err != nil {
		t.Fatalf("loadViperConfig() error = %v", err)
	}
}

func TestGetStreamerConfigReadsHTTPHeaders(t *testing.T) {
	writeConfig(t, `---
db_path: "streamer.sqlite"
gitlab_hostname: "gitlab.example.com"
sources:
  audit_log_path: "/var/log/gitlab/gitlab-rails/audit_json.log"
  auth_log_path: "/var/log/gitlab/gitlab-rails/auth_json.log"
destinations:
  http:
    audit_log_url: "https://example.com/audit-hook"
    auth_log_url: "https://example.com/auth-hook"
    headers:
      Authorization: "Bearer 1234567890"
      X-Custom: "yes"
`)

	cfg, err := getStreamerConfig()
	if err != nil {
		t.Fatalf("getStreamerConfig() error = %v", err)
	}

	// Viper lowercases map keys; http.Header.Set canonicalizes them later.
	want := map[string]string{
		"authorization": "Bearer 1234567890",
		"x-custom":      "yes",
	}
	if len(cfg.HTTPHeaders) != len(want) {
		t.Fatalf("HTTPHeaders = %v, want %v", cfg.HTTPHeaders, want)
	}
	for k, v := range want {
		if cfg.HTTPHeaders[k] != v {
			t.Errorf("HTTPHeaders[%q] = %q, want %q", k, cfg.HTTPHeaders[k], v)
		}
	}

	if cfg.AuditLogForwardingEndpoint != "https://example.com/audit-hook" {
		t.Errorf("AuditLogForwardingEndpoint = %q", cfg.AuditLogForwardingEndpoint)
	}
	if cfg.AuthLogForwardingEndpoint != "https://example.com/auth-hook" {
		t.Errorf("AuthLogForwardingEndpoint = %q", cfg.AuthLogForwardingEndpoint)
	}
	if cfg.GitlabHostname != "gitlab.example.com" {
		t.Errorf("GitlabHostname = %q", cfg.GitlabHostname)
	}
}

func TestGetStreamerConfigWithoutHeaders(t *testing.T) {
	writeConfig(t, `---
db_path: "streamer.sqlite"
sources:
  audit_log_path: "/var/log/gitlab/gitlab-rails/audit_json.log"
destinations:
  syslog:
    server_addr: "localhost:1489"
    protocol: "udp"
    use_leef: true
`)

	cfg, err := getStreamerConfig()
	if err != nil {
		t.Fatalf("getStreamerConfig() error = %v", err)
	}

	if len(cfg.HTTPHeaders) != 0 {
		t.Errorf("HTTPHeaders = %v, want empty", cfg.HTTPHeaders)
	}
	if cfg.SyslogServerAddr != "localhost:1489" {
		t.Errorf("SyslogServerAddr = %q", cfg.SyslogServerAddr)
	}
	if !cfg.UseLEEF {
		t.Error("UseLEEF = false, want true")
	}
}

func TestLoadViperConfigRequiresMandatoryKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("---\ngitlab_hostname: \"gitlab.example.com\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	viper.Reset()
	t.Cleanup(viper.Reset)

	// Neither sources.audit_log_path nor db_path is set.
	err := loadViperConfig(dir, false)
	if err == nil {
		t.Fatal("loadViperConfig() expected an error when required keys are missing")
	}
}

func TestGetStreamerConfigReadsDedupWindowAndDropMessages(t *testing.T) {
	writeConfig(t, `---
db_path: "streamer.sqlite"
sources:
  audit_log_path: "/var/log/gitlab/gitlab-rails/audit_json.log"
dedup_window: "72h"
filters:
  auth_log:
    drop_messages:
      - "IAM JWT authentication attempt when disabled"
      - "Rack_Attack"
`)

	cfg, err := getStreamerConfig()
	if err != nil {
		t.Fatalf("getStreamerConfig() error = %v", err)
	}

	if cfg.DedupWindow != 72*time.Hour {
		t.Errorf("DedupWindow = %v, want 72h", cfg.DedupWindow)
	}
	want := []string{"IAM JWT authentication attempt when disabled", "Rack_Attack"}
	if !slices.Equal(cfg.AuthLogDropMessages, want) {
		t.Errorf("AuthLogDropMessages = %q, want %q", cfg.AuthLogDropMessages, want)
	}
}

func TestGetStreamerConfigNewKeysOptional(t *testing.T) {
	writeConfig(t, `---
db_path: "streamer.sqlite"
sources:
  audit_log_path: "/var/log/gitlab/gitlab-rails/audit_json.log"
`)

	cfg, err := getStreamerConfig()
	if err != nil {
		t.Fatalf("getStreamerConfig() error = %v", err)
	}

	// Zero means "use streamer.DefaultDedupWindow".
	if cfg.DedupWindow != 0 {
		t.Errorf("DedupWindow = %v, want 0 (default)", cfg.DedupWindow)
	}
	if len(cfg.AuthLogDropMessages) != 0 {
		t.Errorf("AuthLogDropMessages = %q, want empty", cfg.AuthLogDropMessages)
	}
}

func TestLoadViperConfigRejectsInvalidDedupWindow(t *testing.T) {
	for _, value := range []string{`"2 days"`, `"-1h"`, `"0s"`} {
		dir := t.TempDir()
		content := "---\ndb_path: \"streamer.sqlite\"\nsources:\n  audit_log_path: \"/tmp/audit_json.log\"\ndedup_window: " + value + "\n"
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		viper.Reset()
		if err := loadViperConfig(dir, false); err == nil {
			t.Errorf("dedup_window: %s: expected a config error", value)
		}
	}
	viper.Reset()
}
