package streamer

import (
	"errors"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

func (s *AuditLogStreamer) updateCurrentGitlabVersion() error {
	log.Debug().Msg("Updating current Gitlab version")
	version, err := getCurrentGitlabVersion()
	if err != nil {
		return err
	}
	s.currentGitlabVersion = version
	return nil
}

func getCurrentGitlabVersion() (string, error) {
	log.Debug().Msg("Getting current Gitlab version")
	content, err := os.ReadFile(GitlabVersionManifestPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(content), "\n")
	if strings.HasPrefix(lines[0], "gitlab-ee") {
		version := strings.Split(lines[0], " ")[1]
		log.Debug().Msgf("Current Gitlab version: %s", version)
		return version, nil
	}

	return "", errors.New("could not get current Gitlab version")
}
