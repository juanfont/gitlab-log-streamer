package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/efekarakus/termcolor"
	streamer "github.com/juanfont/gitlab-log-streamer"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string = ""

var rootCmd = &cobra.Command{
	Use:   "streamer",
	Short: "streamer is a tool to stream Gitlab audit logs to a HTTP endpoint",
	Long: `
headscale is a tool to stream Gitlab audit logs to a HTTP endpoint

https://github.com/juanfont/gitlab-audit-log-streamer`,
}

var watchCmd = &cobra.Command{
	Use:     "watch",
	Short:   "Watch for changes in audit_json.log and send HTTP requests",
	Aliases: []string{"ls", "show"},
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := getStreamerConfig()
		if err != nil {
			log.Fatal().Err(err)
		}

		app, err := streamer.NewAuditLogStreamer(cfg)
		if err != nil {
			log.Fatal().Err(err).Msg("Could not create streamer")
		}

		err = app.Watch()
		if err != nil {
			log.Fatal().Err(err).Msg("Could not watch for changes")
		}

	},
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().
		StringVarP(&cfgFile, "config", "c", "", "config file (default is /etc/streamer/config.yaml)")

	rootCmd.AddCommand(watchCmd)
}

func initConfig() {
	if cfgFile != "" {
		err := loadViperConfig(cfgFile, true)
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("Could not load config")
		}
	} else {
		err := loadViperConfig("", false)
		if err != nil {
			log.Fatal().Caller().Err(err).Msg("Could not load config")
		}
	}
}

func getStreamerConfig() (streamer.Config, error) {
	cfg := streamer.Config{
		AuditLogPath: viper.GetString("audit_log_path"),
		DBpath:       viper.GetString("db_path"),
	}

	return cfg, nil
}

func loadViperConfig(path string, isFile bool) error {
	if isFile {
		viper.SetConfigFile(path)
	} else {
		viper.SetConfigName("config")
		if path == "" {
			viper.AddConfigPath("/etc/streamer/")
			viper.AddConfigPath("$HOME/.streamer")
			viper.AddConfigPath(".")
		} else {
			// For testing
			viper.AddConfigPath(path)
		}
	}

	if err := viper.ReadInConfig(); err != nil {
		log.Warn().Err(err).Msg("Failed to read configuration from disk")
		return fmt.Errorf("fatal error reading config file: %w", err)
	}

	var errorText string
	if viper.GetString("audit_log_path") == "" {
		errorText += "Fatal config error: set audit_log_path in config file\n"
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

func main() {
	var colors bool
	switch l := termcolor.SupportLevel(os.Stderr); l {
	case termcolor.Level16M:
		colors = true
	case termcolor.Level256:
		colors = true
	case termcolor.LevelBasic:
		colors = true
	case termcolor.LevelNone:
		colors = false
	default:
		// no color, return text as is.
		colors = false
	}

	// Adhere to no-color.org manifesto of allowing users to
	// turn off color in cli/services
	if _, noColorIsSet := os.LookupEnv("NO_COLOR"); noColorIsSet {
		colors = false
	}

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
		NoColor:    !colors,
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
