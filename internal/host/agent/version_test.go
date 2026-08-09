package agent

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/version"
)

func cacheWith(t *testing.T, a *Assignment) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "assignment.json")
	require.NoError(t, Save(path, a))
	return &Config{CachePath: path}
}

// TestVersionsAgreeReportsADisagreement.
//
// The failure it names: an agent newer than its server asks for a route the
// server does not have, gets a 404, reports a fetch failure and goes on serving
// its cache. Everything on the host keeps working, so nothing is reported —
// until the cache is the only thing left and the drift is weeks old.
func TestVersionsAgreeReportsADisagreement(t *testing.T) {
	cfg := cacheWith(t, &Assignment{Host: "web-01", ServerVersion: "0.1.0"})

	c := versionsAgree(cfg)
	assert.False(t, c.OK)
	assert.Contains(t, c.Detail, "0.1.0")
	assert.Contains(t, c.Detail, version.Number)
	assert.NotEmpty(t, c.Advice, "a failing check with no advice is a complaint")
}

// TestVersionsAgreeIsQuietWhenTheyMatch: a report where the passing lines say
// nothing is a report people skim.
func TestVersionsAgreeIsQuietWhenTheyMatch(t *testing.T) {
	cfg := cacheWith(t, &Assignment{Host: "web-01", ServerVersion: version.Number})

	c := versionsAgree(cfg)
	assert.True(t, c.OK)
	assert.Contains(t, c.Detail, version.Number)
}

// TestAServerThatNamesNoVersionIsOld.
//
// Nothing before 0.3.0 sent the header, so an empty value is a fact about the
// server rather than a fault — and saying which it is beats reporting a
// mismatch against an empty string.
func TestAServerThatNamesNoVersionIsOld(t *testing.T) {
	cfg := cacheWith(t, &Assignment{Host: "web-01"})

	c := versionsAgree(cfg)
	assert.True(t, c.OK)
	assert.Contains(t, c.Detail, "predates")
}

// TestNoCacheIsNotThisCheckToReport: `enrolled` and the first refresh both speak
// to a missing cache far more usefully than a version comparison with nothing
// to compare against.
func TestNoCacheIsNotThisCheckToReport(t *testing.T) {
	c := versionsAgree(&Config{CachePath: filepath.Join(t.TempDir(), "absent.json")})
	assert.Empty(t, c.Name)
}
