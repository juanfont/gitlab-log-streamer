package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string = ""

func init() {
	if len(os.Args) > 1 &&
		(os.Args[1] == "version") {
		return
	}

	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().
		StringVarP(&cfgFile, "config", "c", "", "config file (default is /etc/gitlab-log-streamer/config.yaml)")
}

func initConfig() {
	if cfgFile == "" {
		cfgFile = os.Getenv("STREAMER_CONFIG")
	}

	if cfgFile != "" {
		err := loadViperConfig(cfgFile, true)
		if err != nil {
			log.Fatal().Caller().Err(err).Msgf("Error loading config file %s", cfgFile)
		}
	} else {
		err := loadViperConfig("", false)
		if err != nil {
			log.Fatal().Caller().Err(err).Msgf("Error loading config")
		}
	}

	viper.SetEnvPrefix("streamer")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	logLevelStr := viper.GetString("log_level")
	if logLevelStr == "" {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		logLevel, err := zerolog.ParseLevel(logLevelStr)
		if err != nil {
			logLevel = zerolog.InfoLevel
		}
		zerolog.SetGlobalLevel(logLevel)
	}
}

var rootCmd = &cobra.Command{
	Use:   "streamer",
	Short: "streamer is a tool to stream Gitlab audit logs to a HTTP endpoint",
	Long: `
headscale is a tool to stream Gitlab audit logs to a HTTP endpoint

https://github.com/juanfont/gitlab-log-streamer`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
