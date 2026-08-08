package store_test

import (
	"context"
	"io/fs"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/store"
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

// TestMigratingDownAndUpAgainReachesTheSameSchema.
//
// The claim a downgrade rests on: after reversing to some point and applying
// forward again, the database is the schema the code expects — not merely one
// that did not error. Compared by asking PostgreSQL for its own column list,
// because a reversal that drops the wrong thing still succeeds and a reversal
// that drops nothing succeeds most cheerfully of all.
func TestMigratingDownAndUpAgainReachesTheSameSchema(t *testing.T) {
	// Its own database, and it has to be. Reversing a migration drops tables,
	// and the shared one is shared — a test that leaves it without
	// webauthn_credentials fails every other test in the package with an error
	// that looks nothing like this one.
	s := newStoreOnOwnDatabase(t)
	ctx := t.Context()

	_, err := s.Migrate(ctx)
	require.NoError(t, err)

	before := schemaShape(t, s)
	applied, err := s.AppliedMigrations(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(applied), 4)

	// Back three, then forward again.
	target := applied[len(applied)-4].Name
	undone, err := s.MigrateDownTo(ctx, target)
	require.NoError(t, err)
	assert.Len(t, undone, 3)

	during := schemaShape(t, s)
	assert.NotEqual(t, before, during,
		"reversing three migrations changed nothing — the reversals are no-ops")

	ran, err := s.Migrate(ctx)
	require.NoError(t, err)
	assert.Len(t, ran, 3, "the reversed migrations should be unapplied and reapply")

	assert.Equal(t, before, schemaShape(t, s),
		"down then up did not reach the schema the code expects")
}

// TestReversingPastAnUnknownMigrationChangesNothing.
//
// Named targets are typed by a person under pressure. A typo must be refused
// rather than interpreted, and it must be refused before anything is dropped.
func TestReversingPastAnUnknownMigrationChangesNothing(t *testing.T) {
	s := newStoreOnOwnDatabase(t)
	ctx := t.Context()
	_, err := s.Migrate(ctx)
	require.NoError(t, err)

	before := schemaShape(t, s)
	_, err = s.MigrateDownTo(ctx, "0007_consent") // missing the .sql
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an applied migration")
	assert.Equal(t, before, schemaShape(t, s), "a refused target changed the schema")
}

// schemaShape is every column of every table, as PostgreSQL sees it.
func schemaShape(t *testing.T, s *store.Store) string {
	t.Helper()
	rows, err := s.Pool().Query(t.Context(), `
		SELECT c.table_name || '.' || c.column_name || ':' || c.data_type
		  FROM information_schema.columns c
		  JOIN information_schema.tables t
		    ON t.table_name = c.table_name AND t.table_schema = c.table_schema
		 WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
		 ORDER BY 1`)
	require.NoError(t, err)
	defer rows.Close()

	var out []string
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		out = append(out, line)
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, out)
	return strings.Join(out, "\n")
}

// newStoreOnOwnDatabase gives a test a database nothing else touches.
//
// For the destructive ones. Everything else shares a database and truncates
// between tests, which is fine for rows and hopeless for schema: a test that
// reverses a migration removes tables the next test expects to exist.
func newStoreOnOwnDatabase(t *testing.T) *store.Store {
	t.Helper()
	ctx := t.Context()

	admin, err := store.Open(ctx, sharedDSN)
	require.NoError(t, err)
	defer admin.Close()

	// Derived from the test name so a failure says which test left it behind,
	// on the rare occasion cleanup does not run.
	name := "schema_" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(t.Name()))

	_, err = admin.Pool().Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize())
	require.NoError(t, err)
	_, err = admin.Pool().Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	require.NoError(t, err)

	dsn, err := url.Parse(sharedDSN)
	require.NoError(t, err)
	dsn.Path = "/" + name

	s, err := store.Open(ctx, dsn.String())
	require.NoError(t, err)
	t.Cleanup(func() {
		s.Close()
		// A fresh connection, because the pool above is closed and the drop
		// cannot run over it. Best effort: a leftover database costs disk in a
		// container that is about to be terminated anyway.
		cleanup, err := store.Open(context.WithoutCancel(ctx), sharedDSN)
		if err != nil {
			return
		}
		defer cleanup.Close()
		_, _ = cleanup.Pool().Exec(context.WithoutCancel(ctx), //nolint:errcheck // best effort; the container is about to be terminated
			"DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize())
	})
	return s
}
