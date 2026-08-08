package store_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// defaultPostgresImage is pinned, not floated.
//
// FOR PORTION OF changed between 19 beta 1 and beta 2, so "latest 19 beta"
// would make the test suite's meaning drift underneath us. Re-run everything
// deliberately when 19 GA lands, then move this constant.
const defaultPostgresImage = "postgres:19beta2"

// postgresImage lets CI run the suite across a version matrix. Locally it is
// the pinned default, so a developer and CI test the same thing by default.
func postgresImage() string {
	if img := os.Getenv("CARDINAL_TEST_POSTGRES_IMAGE"); img != "" {
		return img
	}
	return defaultPostgresImage
}

// sharedDSN is set once by TestMain. Every test runs against one container:
// starting a fresh PostgreSQL per test would be correct but far too slow, so
// tests isolate themselves by truncating instead (see newStore).
var sharedDSN string

// TestMain brings up a real PostgreSQL and applies the migrations.
//
// These tests cannot use a mock or an in-memory substitute. WITHOUT OVERLAPS
// and FOR PORTION OF are database semantics — the invariants under test are
// enforced by PostgreSQL, so testing anything else would only confirm that our
// fake agrees with itself.
func TestMain(m *testing.M) {
	// testing.Short() panics if flags haven't been parsed, and inside TestMain
	// that hasn't happened yet — m.Run() would normally do it.
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping integration tests (-short)")
		os.Exit(0)
	}

	ctx := context.Background()

	container, err := tcpostgres.Run(ctx, postgresImage(),
		tcpostgres.WithDatabase("cardinal_test"),
		tcpostgres.WithUsername("cardinal"),
		tcpostgres.WithPassword("cardinal"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting postgres: %v\n", err)
		os.Exit(1)
	}

	code := run(ctx, container, m)

	if err := testcontainers.TerminateContainer(container); err != nil {
		fmt.Fprintf(os.Stderr, "terminating container: %v\n", err)
	}
	os.Exit(code)
}

// run exists so deferred cleanup and os.Exit don't fight: os.Exit skips defers,
// so the container termination in TestMain must happen after this returns.
func run(ctx context.Context, container *tcpostgres.PostgresContainer, m *testing.M) int {
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection string: %v\n", err)
		return 1
	}
	sharedDSN = dsn

	if err := applyMigrations(ctx, dsn); err != nil {
		fmt.Fprintf(os.Stderr, "applying migrations: %v\n", err)
		return 1
	}
	return m.Run()
}

// applyMigrations runs the real migration files, not a test-only schema.
// A schema that drifts from production is a test suite that proves nothing.
func applyMigrations(ctx context.Context, dsn string) error {
	s, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer s.Close()

	paths, err := filepath.Glob(filepath.Join("..", "..", "migrations", "*.sql"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("no migrations found — is the working directory wrong?")
	}

	for _, path := range paths {
		sql, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if _, err := s.Pool().Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("applying %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

// newStore returns a Store against a clean database.
//
// Truncation rather than a fresh container per test, for speed. The event
// journal is append-only and protected by rules that make DELETE a no-op, so
// TRUNCATE is the only way to reset it — which is fine here and impossible in
// production, exactly as intended.
func newStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := t.Context()

	s, err := store.Open(ctx, sharedDSN)
	require.NoError(t, err)
	t.Cleanup(s.Close)

	// The table list is derived, not hardcoded.
	//
	// A hardcoded list silently stops isolating tests the moment someone adds a
	// table and forgets to update it — which is exactly what happened once
	// already, producing a failure that looked like a logic bug rather than
	// leaked state. Deriving it means new tables are covered automatically.
	//
	// Partitions are excluded because truncating the partitioned parent already
	// clears them, and naming both is an error.
	rows, err := s.Pool().Query(ctx, `
		SELECT c.relname
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public'
		   AND c.relkind IN ('r', 'p')
		   AND NOT c.relispartition`)
	require.NoError(t, err)

	var tables []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		tables = append(tables, pgx.Identifier{name}.Sanitize())
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.NotEmpty(t, tables, "no tables found — did migrations run?")

	_, err = s.Pool().Exec(ctx,
		"TRUNCATE "+strings.Join(tables, ", ")+" RESTART IDENTITY CASCADE")
	require.NoError(t, err)

	return s
}

// mustCreate makes an entity and fails the test if it can't.
func mustCreate(t *testing.T, s *store.Store, typ directory.Type, name string) *directory.Entity {
	t.Helper()
	e, err := directory.NewEntity(typ, name, "")
	require.NoError(t, err)
	require.NoError(t, s.CreateEntity(t.Context(), e, nil))
	return e
}

// Fixed reference points, so tests read as scenarios rather than arithmetic.
var (
	jan1 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mar1 = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	jun1 = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	sep1 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	dec1 = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
)

// uuidMust parses a UUID in a test, failing loudly rather than returning a zero
// value that would produce a confusing assertion failure later.
func uuidMust(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	require.NoError(t, err)
	return id
}
