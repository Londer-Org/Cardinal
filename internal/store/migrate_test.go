package store_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/store"
	"go.londer.be/cardinal/migrations"
)

// TestASchemaFromTheFutureIsToleratedUnlessItSaysOtherwise.
//
// The rollback case, and the reason the answer changed. Refusing every schema a
// binary did not recognise made rolling back impossible without a schema
// operation — which is the complexity the expand-only rule exists to remove.
//
// Migrations only add, so drift on its own is fine. What refuses is a migration
// whose author declared it incompatible, and that declaration lives in the row
// rather than in the file, because a binary that predates the migration cannot
// read the file.
func TestASchemaFromTheFutureIsToleratedUnlessItSaysOtherwise(t *testing.T) {
	s := newStoreOnOwnDatabase(t)
	ctx := t.Context()
	_, err := s.Migrate(ctx)
	require.NoError(t, err)

	drift, err := s.SchemaAhead(ctx)
	require.NoError(t, err)
	assert.Empty(t, drift.Unknown, "a database this binary migrated is not ahead of it")
	assert.Empty(t, drift.Blocking)

	// What an ordinary newer release leaves behind: a migration this build has
	// never heard of, which added something and said nothing.
	_, err = s.Pool().Exec(ctx,
		`INSERT INTO schema_migrations (name, digest) VALUES ($1, $2)`,
		"9999_added_a_column.sql", "deadbeef")
	require.NoError(t, err)

	drift, err = s.SchemaAhead(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"9999_added_a_column.sql"}, drift.Unknown)
	assert.Empty(t, drift.Blocking,
		"an ordinary migration must not block an older build, or rollback needs a "+
			"schema operation again")

	// And what a declared incompatibility leaves behind.
	_, err = s.Pool().Exec(ctx,
		`INSERT INTO schema_migrations (name, digest, breaking) VALUES ($1, $2, $3)`,
		"9998_removed_a_column.sql", "cafebabe", "dropped entities.display_name")
	require.NoError(t, err)

	drift, err = s.SchemaAhead(ctx)
	require.NoError(t, err)
	assert.Len(t, drift.Unknown, 2)
	assert.Equal(t,
		map[string]string{"9998_removed_a_column.sql": "dropped entities.display_name"},
		drift.Blocking,
		"the reason has to survive into the database; the older binary cannot read "+
			"the migration file that explains itself")
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

// TestADatabaseBehindTheBinaryIsRefused.
//
// The upgrade case, and the one Kubernetes made concrete: a Job's pod template
// is immutable, so `kubectl apply` with a new image tag updates the Deployment
// and rejects the migration Job. The new server rolls out, the migration never
// runs, and nothing notices — "some migration has been applied" is true and was
// all anything checked.
func TestADatabaseBehindTheBinaryIsRefused(t *testing.T) {
	s := newStoreOnOwnDatabase(t)
	ctx := t.Context()

	// A database nobody has migrated is behind by everything, which is what a
	// fresh install looks like and what the message has to say.
	behind, err := s.SchemaBehind(ctx)
	require.NoError(t, err)
	known, err := migrations.Up()
	require.NoError(t, err)
	assert.Equal(t, known, behind, "an empty database is missing every migration")

	// Migrated, and now behind by nothing. Without this the test would pass on
	// an implementation that always claimed everything was missing.
	_, err = s.Migrate(ctx)
	require.NoError(t, err)
	behind, err = s.SchemaBehind(ctx)
	require.NoError(t, err)
	assert.Empty(t, behind, "a fully migrated database is not behind")

	// Now the upgrade: a new build contains a migration this database has never
	// been given. Forgetting the newest row is what that looks like from here,
	// and it is what `kubectl apply` rejecting the migration Job produced.
	applied, err := s.AppliedMigrations(ctx)
	require.NoError(t, err)
	newest := applied[len(applied)-1].Name
	_, err = s.Pool().Exec(ctx, `DELETE FROM schema_migrations WHERE name = $1`, newest)
	require.NoError(t, err)

	behind, err = s.SchemaBehind(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{newest}, behind)
}
