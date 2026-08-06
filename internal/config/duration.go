package config

import (
	"fmt"
	"time"
)

// Duration is a time.Duration written the way people write them.
//
// TOML has no duration type, so the alternatives are a bare number — which
// forces every reader to remember whether `8` meant hours or seconds, and every
// writer to guess — or a string Go already knows how to parse. `idle = "8h"`
// says what it means.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalText parses "8h", "30m", "7d"-style values.
//
// Days are handled here because time.ParseDuration does not know them, and an
// absolute session limit written in hours is a number nobody reads correctly:
// "168h" is a week, and only after doing the arithmetic.
func (d *Duration) UnmarshalText(text []byte) error {
	value := string(text)

	if days, ok := parseDays(value); ok {
		*d = Duration(days)
		return nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("config: %q is not a duration; write it like \"8h\", "+
			"\"30m\" or \"7d\"", value)
	}
	if parsed <= 0 {
		return fmt.Errorf("config: %q is not a positive duration", value)
	}
	*d = Duration(parsed)
	return nil
}

func parseDays(value string) (time.Duration, bool) {
	if len(value) < 2 || value[len(value)-1] != 'd' {
		return 0, false
	}
	var days float64
	if _, err := fmt.Sscanf(value[:len(value)-1], "%g", &days); err != nil || days <= 0 {
		return 0, false
	}
	return time.Duration(days * 24 * float64(time.Hour)), true
}

// orDefault returns the configured value, or the fallback when unset.
func (d Duration) orDefault(fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return time.Duration(d)
}
