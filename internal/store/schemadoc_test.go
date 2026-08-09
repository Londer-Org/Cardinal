package store_test

import (
	"context"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/store"
)

// TestSchemaDocumentMatchesTheSchema fails when docs/schema.md is stale.
//
// The document is generated from a live database by `make schema`, and its own
// header says a schema document maintained separately from the schema is "wrong
// within a month, and then worse than absent, because someone believes it".
// Nothing enforced that, and it went three migrations stale — missing the
// Shared Signals tables, SCIM's external_id and the token scopes column
// entirely. It was noticed by somebody regenerating it for an unrelated reason.
//
// It runs against its own database rather than the shared one, because the two
// are not built the same way. The shared harness applies migration SQL directly
// with Exec, and `schema_migrations` is created by Store.Migrate in Go rather
// than by any migration — so the shared database does not have that table and
// the document does. Comparing against it would report a difference that is
// true of the harness and not of any deployment.
func TestSchemaDocumentMatchesTheSchema(t *testing.T) {
	// Not parallel: it shells out to `go run` and creates a database, and
	// neither is worth multiplying.
	ctx := t.Context()

	dsn := migratedDatabase(t)

	cmd := exec.CommandContext(ctx, "go", "run", "./tools/schemadoc", "-check")
	// The tool resolves docs/schema.md relative to the working directory, which
	// is how `make schema` invokes it.
	cmd.Dir = "../.."
	cmd.Env = append(cmd.Environ(), "CARDINAL_DSN="+dsn)

	out, err := cmd.CombinedOutput()
	if err == nil {
		return
	}

	// The tool names the first differing line and says how to fix it, so its
	// message is passed through rather than summarised.
	t.Errorf("the committed schema document no longer matches the migrations:\n\n%s",
		strings.TrimSpace(string(out)))
}

// migratedDatabase creates a database and migrates it the way a deployment is
// migrated — through Store.Migrate, not by executing the files.
//
// That distinction is the reason this helper exists rather than reusing
// freshInstall: the migrator creates schema_migrations itself, records a digest
// per migration, and is the only path that produces the schema an operator
// actually gets.
func migratedDatabase(t *testing.T) string {
	t.Helper()
	ctx := t.Context()

	name := "schemadoc_" + strings.ReplaceAll(uuid.New().String()[:8], "-", "")

	admin, err := pgx.Connect(ctx, sharedDSN)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	require.NoError(t, err)
	require.NoError(t, admin.Close(ctx))

	u, err := url.Parse(sharedDSN)
	require.NoError(t, err)
	u.Path = "/" + name
	dsn := u.String()

	s, err := store.Open(ctx, dsn)
	require.NoError(t, err)
	applied, err := s.Migrate(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, applied, "no migrations ran, so the comparison would be against an empty schema")
	s.Close()

	t.Cleanup(func() {
		// Dropped from a connection to the original database, since the one
		// being dropped cannot be the one connected to it.
		cleanup, connErr := pgx.Connect(context.WithoutCancel(ctx), sharedDSN)
		if connErr != nil {
			return
		}
		//nolint:errcheck // a scratch database left behind dies with the container
		defer cleanup.Close(context.WithoutCancel(ctx))
		//nolint:errcheck // the drop is tidiness, and its failure must not fail a passing test
		cleanup.Exec(context.WithoutCancel(ctx),
			"DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})
	return dsn
}
