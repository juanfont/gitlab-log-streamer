package cli

import (
	"errors"
	"strings"
	"time"

	streamer "github.com/juanfont/gitlab-log-streamer"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func getStreamerConfig() (streamer.Config, error) {
	cfg := streamer.Config{
		ListenAddr:                 viper.GetString("listen_addr"),
		AuditLogForwardingEndpoint: viper.GetString("destinations.http.audit_log_url"),
		AuthLogForwardingEndpoint:  viper.GetString("destinations.http.auth_log_url"),
		GitlabHostname:             viper.GetString("gitlab_hostname"),
		AuditLogPath:               viper.GetString("sources.audit_log_path"),
		AuthLogPath:                viper.GetString("sources.auth_log_path"),
		DBpath:                     viper.GetString("db_path"),
		HTTPHeaders:                viper.GetStringMapString("destinations.http.headers"),
		SyslogServerAddr:           viper.GetString("destinations.syslog.server_addr"),
		SyslogProtocol:             viper.GetString("destinations.syslog.protocol"),
		UseLEEF:                    viper.GetBool("destinations.syslog.use_leef"),
		DedupWindow:                viper.GetDuration("dedup_window"),
		AuthLogDropMessages:        viper.GetStringSlice("filters.auth_log.drop_messages"),
	}

	return cfg, nil
}

func loadViperConfig(path string, isFile bool) error {
	if isFile {
		viper.SetConfigFile(path)
	} else {
		viper.SetConfigName("config")
		if path == "" {
			viper.AddConfigPath("/etc/gitlab-log-streamer")
			viper.AddConfigPath("$HOME/.gitlab-log-streamer")
			viper.AddConfigPath(".")
		} else {
			// For testing
			viper.AddConfigPath(path)
		}
	}

	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	logLevelStr := viper.GetString("log_level")
	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		logLevel = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(logLevel)

	var errorText string
	if viper.GetString("sources.audit_log_path") == "" {
		errorText += "Fatal config error: set sources.audit_log_path in config file\n"
	}

	if viper.GetString("db_path") == "" {
		errorText += "Fatal config error: set db_path in config file\n"
	}

	// viper.GetDuration silently returns 0 for unparsable values, which would
	// quietly fall back to the default window.
	if viper.IsSet("dedup_window") {
		window, err := time.ParseDuration(viper.GetString("dedup_window"))
		if err != nil || window <= 0 {
			errorText += "Fatal config error: dedup_window must be a positive duration, e.g. \"48h\"\n"
		}
	}

	if errorText != "" {
		//nolint
		return errors.New(strings.TrimSuffix(errorText, "\n"))
	} else {
		return nil
	}
}
