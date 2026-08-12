package command

import (
	"errors"
	"flag"
	"io"
	"time"

	"go.londer.be/cardinal/internal/cli/api"
)

// parse reads flags that may appear before or after the positional arguments,
// which is what people type regardless of what the flag package prefers.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)

	var positional []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	return positional, nil
}

// instant parses an -at value. The zero time means now.
func instant(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, errors.New("-at must be an RFC3339 instant, e.g. 2026-03-14T09:00:00Z")
	}
	return at, nil
}

func describeInstant(at time.Time) string {
	if at.IsZero() {
		return "now"
	}
	return at.UTC().Format(time.RFC3339)
}

func period(g api.Grant) string {
	if g.Until == nil {
		return "from " + g.From.Format(time.RFC3339) + ", no end"
	}
	return "from " + g.From.Format(time.RFC3339) + " until " + g.Until.Format(time.RFC3339)
}
