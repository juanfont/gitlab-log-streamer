package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "dev"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version.",
	Long:  "The version of gitlab-log-streamer.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(Version)
	},
}
