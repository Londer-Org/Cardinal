package store_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/migrations"
)

// TestASchemaFromTheFutureIsRefused.
//
// The downgrade case. An older binary against a newer database used to start
// happily and then fail one request at a time, wherever a code path first
// touched a column it did not know about — a symptom that looks like a bug in
// whichever feature was unlucky rather than like the wrong version running.
func TestASchemaFromTheFutureIsRefused(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	// A database with no schema_migrations at all is not "ahead" — it is a fresh
	// install, and saying anything else would refuse to start every new
	// deployment. This asserted a 42P01 out of the first implementation.
	ahead, err := s.SchemaAhead(ctx)
	require.NoError(t, err)
	assert.Empty(t, ahead, "a database nobody has migrated is not ahead of anything")

	// Now the ordinary case: the table exists and holds only what this binary
	// knows. Without this the test below would pass on an implementation that
	// called everything ahead.
	_, err = s.Pool().Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       text        PRIMARY KEY,
			digest     text        NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`)
	require.NoError(t, err)
	known, err := migrations.Up()
	require.NoError(t, err)
	for _, name := range known {
		_, err = s.Pool().Exec(ctx,
			`INSERT INTO schema_migrations (name, digest) VALUES ($1, 'x')`, name)
		require.NoError(t, err)
	}
	ahead, err = s.SchemaAhead(ctx)
	require.NoError(t, err)
	assert.Empty(t, ahead, "a database holding exactly this binary's set is not ahead")

	// What a newer Cardinal leaves behind: a row naming a migration this build
	// has never heard of.
	_, err = s.Pool().Exec(ctx,
		`INSERT INTO schema_migrations (name, digest) VALUES ($1, $2)`,
		"9999_from_the_future.sql", "deadbeef")
	require.NoError(t, err)

	ahead, err = s.SchemaAhead(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"9999_from_the_future.sql"}, ahead)
}

// TestDownMigrationsAreNotAppliedAsForwardOnes.
//
// `.down.sql` matches the same embed pattern as the migration it reverses, so a
// naive glob applies every drop immediately after the create that made it — and
// the first `cardinal migrate` against an empty database leaves no schema at
// all. Worth a test rather than a comment, because the failure is total and the
// cause is one character of a filename.
func TestDownMigrationsAreNotAppliedAsForwardOnes(t *testing.T) {
	up, err := migrations.Up()
	require.NoError(t, err)
	require.NotEmpty(t, up)

	for _, name := range up {
		assert.False(t, strings.HasSuffix(name, ".down.sql"),
			"%s is a reversal and must not be in the forward list", name)
	}

	all, err := fs.Glob(migrations.FS, "*.sql")
	require.NoError(t, err)
	assert.LessOrEqual(t, len(up), len(all))
}
