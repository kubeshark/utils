package race

import (
	"fmt"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/nxadm/tail"
	"github.com/rs/zerolog/log"
)

const logSeparator string = "=================="
const redacted string = "[REDACTED]"

func WatchRaceLogs() {
	if !isRaceFlagEnabled() {
		return
	}

	t, err := tail.TailFile(
		findRaceLogFile(),
		tail.Config{
			Follow: true,
			ReOpen: true,
		},
	)
	if err != nil {
		log.Error().Err(err).Send()
	}

	var buffer []string

	for line := range t.Lines {
		if line.Text == logSeparator {
			msg := strings.Join(buffer, "\n")
			buffer = make([]string, 0)

			msg = strings.TrimPrefix(msg, logSeparator)
			msg = strings.TrimSuffix(msg, logSeparator)
			msg = strings.TrimSpace(msg)
			if msg != "" {
				log.Error().Str("type", "race").Msg(redact(msg))
			}
		}

		buffer = append(buffer, line.Text)
	}
}

func findRaceLogFile() string {
	for {
		time.Sleep(1 * time.Second)

		matches, err := filepath.Glob("/tmp/kubeshark-race.log.*")
		if err != nil {
			log.Error().Err(err).Send()
			continue
		}

		if len(matches) > 0 {
			return matches[0]
		}
	}
}

func isRaceFlagEnabled() bool {
	b, ok := debug.ReadBuildInfo()
	if !ok {
		log.Error().Err(fmt.Errorf("could not read build info")).Send()
		return false
	}

	for _, s := range b.Settings {
		if s.Key == "-race" && s.Value == "true" {
			return true
		}
	}
	return false
}

func redact(log string) string {
	splitted := strings.Split(log, "\n\n")
	log = strings.Join(splitted[:2], "\n\n")
	return regexp.MustCompile("goroutine [0-9]+").
		ReplaceAllString(
			regexp.MustCompile("0[xX][0-9a-fA-F]+").
				ReplaceAllString(log, redacted),
			redacted,
		)
}
