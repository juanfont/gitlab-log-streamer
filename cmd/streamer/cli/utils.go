package cli

import (
	"errors"
	"strings"

	streamer "github.com/juanfont/gitlab-log-streamer"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

func getStreamerConfig() (streamer.Config, error) {
	cfg := streamer.Config{
		AuditLogForwardingEndpoint: viper.GetString("destinations.http.audit_log_url"),
		AuthLogForwardingEndpoint:  viper.GetString("destinations.http.auth_log_url"),
		GitlabHostname:             viper.GetString("gitlab_hostname"),
		AuditLogPath:               viper.GetString("sources.audit_log_path"),
		AuthLogPath:                viper.GetString("sources.auth_log_path"),
		DBpath:                     viper.GetString("db_path"),
		SyslogServerAddr:           viper.GetString("destinations.syslog.server_addr"),
		SyslogProtocol:             viper.GetString("destinations.syslog.protocol"),
		UseLEEF:                    viper.GetBool("destinations.syslog.use_leef"),
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

	if errorText != "" {
		//nolint
		return errors.New(strings.TrimSuffix(errorText, "\n"))
	} else {
		return nil
	}
}
