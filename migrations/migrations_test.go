package migrations_test

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/migrations"
)

// irreversible lists migrations that deliberately ship no reversal.
//
// One entry, and it should stay that way. Below the foundation is not an older
// schema, it is no schema — the reversal of "create everything" is dropping the
// database, which is not a migration and should not pretend to be one.
var irreversible = map[string]string{
	"0001_foundation.sql": "below this is an empty database, not an older schema",
}

// TestEveryMigrationHasAReversalOrSaysWhyNot.
//
// The rule that keeps downgrade real rather than aspirational: a migration
// added without a reversal fails here, at the moment it is written, rather than
// during the incident where somebody needs it.
func TestEveryMigrationHasAReversalOrSaysWhyNot(t *testing.T) {
	up, err := migrations.Up()
	require.NoError(t, err)
	require.NotEmpty(t, up)

	for _, name := range up {
		t.Run(name, func(t *testing.T) {
			_, ok := migrations.Down(name)
			if reason, declared := irreversible[name]; declared {
				assert.False(t, ok,
					"%s is declared irreversible but ships a reversal — remove one "+
						"of the two claims (%s)", name, reason)
				return
			}
			assert.True(t, ok,
				"%s has no .down.sql. Write one, or add it to `irreversible` with "+
					"the reason — a downgrade path that exists for some migrations "+
					"and silently not others is worse than none", name)
		})
	}
}

var (
	createTable = regexp.MustCompile(`(?is)CREATE TABLE (?:IF NOT EXISTS )?([a-z_0-9]+)(.*?);`)
	dropTable   = regexp.MustCompile(`(?i)DROP TABLE (?:IF EXISTS )?([a-z_0-9]+)`)
	partitionOf = regexp.MustCompile(`(?i)PARTITION OF`)
)

// TestAReversalDropsExactlyWhatItsMigrationCreated.
//
// `DROP TABLE IF EXISTS a_name_with_a_typo` succeeds and does nothing, so a
// reversal naming a table that never existed reports success while leaving the
// schema exactly as it was. Writing these by hand produced four such mistakes —
// two invented names and several real tables missed — none of which any amount
// of running them would have revealed.
func TestAReversalDropsExactlyWhatItsMigrationCreated(t *testing.T) {
	up, err := migrations.Up()
	require.NoError(t, err)

	for _, name := range up {
		down, ok := migrations.Down(name)
		if !ok {
			continue
		}
		t.Run(name, func(t *testing.T) {
			body, err := migrations.FS.ReadFile(name)
			require.NoError(t, err)

			created := map[string]bool{}
			for _, m := range createTable.FindAllStringSubmatch(string(body), -1) {
				// Partitions go with their parent, and naming them separately
				// would be wrong the first year somebody adds another.
				if partitionOf.MatchString(m[2]) {
					continue
				}
				created[strings.ToLower(m[1])] = true
			}
			dropped := map[string]bool{}
			for _, m := range dropTable.FindAllStringSubmatch(string(down), -1) {
				dropped[strings.ToLower(m[1])] = true
			}

			for name := range created {
				assert.True(t, dropped[name],
					"the migration creates %q and the reversal does not drop it", name)
			}
			for name := range dropped {
				assert.True(t, created[name],
					"the reversal drops %q, which this migration never created — "+
						"IF EXISTS makes that a silent no-op", name)
			}
		})
	}
}

// TestReversalsAreNotMistakenForMigrations.
//
// `<name>.down.sql` matches the same embed pattern as the migration it reverses.
// A forward list built from a bare glob applies every drop immediately after the
// create that made it, and the first migration of an empty database leaves no
// schema at all.
func TestReversalsAreNotMistakenForMigrations(t *testing.T) {
	up, err := migrations.Up()
	require.NoError(t, err)
	for _, name := range up {
		assert.False(t, strings.HasSuffix(name, ".down.sql"), "%s is a reversal", name)
	}

	all, err := fs.Glob(migrations.FS, "*.sql")
	require.NoError(t, err)
	assert.Greater(t, len(all), len(up), "the reversals should be embedded too")
}
