package config_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/config"
)

// write puts a configuration file somewhere Load can read it.
func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cardinal.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

const minimal = `
[server]
public_url = "https://id.example.com"
cookie_domain = "example.com"
[database]
dsn = "postgres://cardinal:hunter2@db.internal:5432/cardinal?sslmode=disable"
[webauthn]
rp_id = "example.com"
rp_display_name = "Example"
origins = ["https://id.example.com"]
`

func find(t *testing.T, report []config.Setting, section, name string) config.Setting {
	t.Helper()
	for _, s := range report {
		if s.Section == section && s.Name == name {
			return s
		}
	}
	t.Fatalf("%s.%s is not in the report", section, name)
	return config.Setting{}
}

// TestNoSecretReachesTheReport.
//
// The one thing this page must never do. It is read by whoever can reach the
// console, and a connection string carries a password inline — so a report that
// renders values faithfully would hand the database credential to anybody
// standing behind an administrator.
func TestNoSecretReachesTheReport(t *testing.T) {
	cfg, err := config.Load(write(t, minimal+`
[oidc]
enabled = true
signing_key_encryption_key = "an-oidc-key-that-must-not-appear"
[ssh]
enabled = true
ca_encryption_key = "an-ssh-key-that-must-not-appear"
`))
	require.NoError(t, err)

	report := cfg.Report()
	var rendered strings.Builder
	for _, s := range report {
		rendered.WriteString(s.Value)
		rendered.WriteString("\n")
	}
	whole := rendered.String()

	for _, secret := range []string{
		"hunter2",
		"an-oidc-key-that-must-not-appear",
		"an-ssh-key-that-must-not-appear",
	} {
		assert.NotContains(t, whole, secret,
			"a secret reached the report; whoever can read the console can now read it")
	}

	// And the questions that are worth answering still are.
	assert.Equal(t, "set", find(t, report, "oidc", "signing_key_encryption_key").Value)
	assert.True(t, find(t, report, "database", "dsn").Secret)
	assert.Contains(t, find(t, report, "database", "dsn").Value, "db.internal",
		"redaction removed the host as well, which leaves the report unable to "+
			"answer which database this is")
	assert.Contains(t, find(t, report, "database", "dsn").Value, "cardinal",
		"the user name is not the secret and is worth seeing")
}

// TestAValueFromTheFileIsNotAValueNobodyChose.
//
// The distinction the report exists for. A default that happens to equal what
// somebody would have picked looks identical in the running config and is a
// completely different fact — one of them means nobody has decided.
func TestAValueFromTheFileIsNotAValueNobodyChose(t *testing.T) {
	cfg, err := config.Load(write(t, minimal+`
[sessions]
idle = "2h"
`))
	require.NoError(t, err)
	report := cfg.Report()

	idle := find(t, report, "sessions", "idle")
	assert.Equal(t, config.SourceFile, idle.Source)
	assert.Equal(t, "2h0m0s", idle.Value)

	// Not set anywhere, and reported as such rather than as a decision.
	absolute := find(t, report, "sessions", "absolute")
	assert.Equal(t, config.SourceDefault, absolute.Source)
	assert.NotEmpty(t, absolute.Value, "a default still has a value worth showing")
}

// TestIgnoredSettingsAreStillIgnored.
//
// The list of settings nothing reads is hand-maintained, which makes it exactly
// the kind of thing that stops being true without anybody noticing — and a
// stale list of known problems is the same lie it exists to expose.
//
// So it is checked against the code. Each entry must still have no reader
// outside the config package; the moment one gains one, this fails and the
// entry has to go.
func TestIgnoredSettingsAreStillIgnored(t *testing.T) {
	cfg, err := config.Load(write(t, minimal))
	require.NoError(t, err)

	// Field names, because the report speaks TOML and the code speaks Go.
	fields := map[string]string{
		"database.max_conns":         "MaxConns",
		"database.conn_max_lifetime": "ConnMaxLifetime",
		"recovery.email_enabled":     "EmailEnabled",
		"recovery.email_domains":     "EmailDomains",
	}

	for _, s := range cfg.Report() {
		if s.Ignored == "" {
			continue
		}
		key := s.Section + "." + s.Name
		field, known := fields[key]
		require.True(t, known,
			"%s is marked ignored and this test does not know which Go field it is; "+
				"add it, or the claim cannot be checked", key)

		readers := readersOf(t, field)
		assert.Empty(t, readers,
			"%s is marked ignored in the report, and %s is read by %v — either the "+
				"setting now works and the entry should go, or something reads it "+
				"and does nothing with it", key, field, readers)
	}
}

// readersOf finds Go files outside internal/config that mention a field.
//
// Crude on purpose: a false positive here means somebody looks, which is the
// right direction for a check whose whole job is to stop a stale claim.
func readersOf(t *testing.T, field string) []string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "grep", "-rl", "--include=*.go",
		"\\."+field+"\\b", "../../internal", "../../cmd").Output()
	if err != nil {
		// grep exits 1 when it finds nothing, which is the answer being looked
		// for rather than a failure.
		return nil
	}
	var readers []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || strings.Contains(line, "internal/config/") {
			continue
		}
		readers = append(readers, line)
	}
	return readers
}
