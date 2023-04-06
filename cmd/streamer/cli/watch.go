package cli

import (
	streamer "github.com/juanfont/gitlab-log-streamer"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(watchCmd)
}

var watchCmd = &cobra.Command{
	Use:     "watch",
	Short:   "Watch for changes in audit_json.log and send HTTP requests",
	Aliases: []string{"w"},
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
