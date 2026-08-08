package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/migrations"
)

// migrationLock serialises migrators.
//
// Two instances starting at once — a rolling deploy, a scaled service — would
// otherwise both see an unapplied migration and both try to apply it. A
// session-level advisory lock makes the second wait and then find nothing to do.
const migrationLock int64 = 0x43415244_4D494752 // "CARDMIGR"

// AppliedMigration records a migration that has run.
type AppliedMigration struct {
	Name   string
	Digest string
}

// Migrate applies any unapplied migrations, in filename order.
//
// Idempotent, so it is safe to run on every start. It is nonetheless invoked as
// an explicit command rather than automatically by `serve`: a schema change
// during startup of one replica while others are still serving the old schema
// is how rolling deploys break, and that should be a decision rather than a
// side effect.
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	entries, err := migrations.Up()
	if err != nil {
		return nil, fmt.Errorf("store: listing migrations: %w", err)
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquiring connection: %w", err)
	}
	defer conn.Release()

	if _, execErr := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); execErr != nil {
		return nil, fmt.Errorf("store: taking migration lock: %w", execErr)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), //nolint:errcheck // deliberate
			`SELECT pg_advisory_unlock($1)`, migrationLock)
	}()

	if _, execErr := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       text        PRIMARY KEY,
			digest     text        NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); execErr != nil {
		return nil, fmt.Errorf("store: creating migration table: %w", execErr)
	}

	applied := map[string]string{}
	rows, err := conn.Query(ctx, `SELECT name, digest FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: reading applied migrations: %w", err)
	}
	for rows.Next() {
		var name, digest string
		if err := rows.Scan(&name, &digest); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scanning applied migration: %w", err)
		}
		applied[name] = digest
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var ran []string
	for _, name := range entries {
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("store: reading %s: %w", name, err)
		}
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])

		if previous, seen := applied[name]; seen {
			// An edited migration means the database and the source disagree
			// about what the schema is. Refusing is the only honest answer:
			// re-running would fail on already-created objects, and skipping
			// silently would leave the difference undetected until something
			// unrelated broke.
			if previous != digest {
				return nil, fmt.Errorf(
					"store: migration %s has changed since it was applied "+
						"(recorded %s, now %s) — migrations are immutable once "+
						"applied; add a new one instead",
					name, previous[:12], digest[:12])
			}
			continue
		}

		// Each migration runs in its own transaction, so a failure leaves the
		// database at a known migration boundary rather than partway through
		// an unknown one.
		err = s.InTx(ctx, func(tx pgx.Tx) error {
			if _, execErr := tx.Exec(ctx, string(body)); execErr != nil {
				return fmt.Errorf("applying %s: %w", name, execErr)
			}
			_, execErr := tx.Exec(ctx,
				`INSERT INTO schema_migrations (name, digest) VALUES ($1, $2)`,
				name, digest)
			return execErr
		})
		if err != nil {
			return ran, fmt.Errorf("store: %w", err)
		}
		ran = append(ran, name)
	}

	return ran, nil
}

// AppliedMigrations lists what has been applied, for `cardinal migrate -status`.
func (s *Store) AppliedMigrations(ctx context.Context) ([]AppliedMigration, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT name, digest FROM schema_migrations ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading applied migrations: %w", err)
	}
	defer rows.Close()

	var out []AppliedMigration
	for rows.Next() {
		var m AppliedMigration
		if err := rows.Scan(&m.Name, &m.Digest); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ErrSchemaAhead reports a database migrated by a newer Cardinal than this one.
//
// The downgrade case, and until this existed it was silent: an older binary
// started happily against a newer schema and failed later, one request at a
// time, in whichever code path first touched a column it did not know about.
var ErrSchemaAhead = errors.New("store: the database schema is newer than this binary")

// SchemaAhead names migrations the database has applied and this binary does not
// contain.
//
// Nothing else can detect this. `schema_migrations` records what ran, and a
// binary knows only what it embeds, so the difference between them is exactly
// "changes made by a version I am not" — which is the question worth asking
// before serving a single request.
//
// The reverse case, a database behind the binary, is not an error here: that is
// an unapplied migration, and `cardinal migrate` is how it gets applied.
func (s *Store) SchemaAhead(ctx context.Context) ([]string, error) {
	known, err := migrations.Up()
	if err != nil {
		return nil, fmt.Errorf("store: listing migrations: %w", err)
	}
	mine := make(map[string]struct{}, len(known))
	for _, name := range known {
		mine[name] = struct{}{}
	}

	// to_regclass rather than a bare SELECT, because a database nobody has
	// migrated yet has no schema_migrations at all — the fresh-install case,
	// where the honest answer is "nothing has been applied, so nothing is ahead"
	// and not a 42P01 that reads like the database is broken.
	var exists bool
	if scanErr := s.pool.QueryRow(ctx,
		`SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&exists); scanErr != nil {
		return nil, fmt.Errorf("store: looking for the migration table: %w", scanErr)
	}
	if !exists {
		return nil, nil
	}

	rows, err := s.pool.Query(ctx, `SELECT name FROM schema_migrations ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: reading applied migrations: %w", err)
	}
	defer rows.Close()

	var ahead []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if _, ok := mine[name]; !ok {
			ahead = append(ahead, name)
		}
	}
	return ahead, rows.Err()
}

// ErrSchemaBehind reports a database missing migrations this binary contains.
//
// The other half of ErrSchemaAhead, and the one an upgrade walks into. Nothing
// detected it: the server started against a schema missing the very columns the
// new code was written for and failed later, one request at a time.
var ErrSchemaBehind = errors.New("store: the database is missing migrations this binary contains")

// SchemaBehind names migrations this binary contains and the database has not
// applied.
//
// Deliberately not the same as "is anything pending" asked of the migrator: this
// runs at startup, in every deployment shape, so the ordering — migrate, then
// deploy — is enforced by the binary rather than by whatever applied the
// manifests remembering to.
func (s *Store) SchemaBehind(ctx context.Context) ([]string, error) {
	known, err := migrations.Up()
	if err != nil {
		return nil, fmt.Errorf("store: listing migrations: %w", err)
	}

	var exists bool
	if scanErr := s.pool.QueryRow(ctx,
		`SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&exists); scanErr != nil {
		return nil, fmt.Errorf("store: looking for the migration table: %w", scanErr)
	}
	if !exists {
		// Nothing has ever been applied, so everything is pending. A fresh
		// install, and the message the caller prints tells them so.
		return known, nil
	}

	applied := map[string]struct{}{}
	rows, err := s.pool.Query(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: reading applied migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		applied[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var behind []string
	for _, name := range known {
		if _, ok := applied[name]; !ok {
			behind = append(behind, name)
		}
	}
	return behind, nil
}

// ErrIrreversible reports a migration that must be undone before one that
// cannot be.
var ErrIrreversible = errors.New("store: migration has no reversal")

// MigrateDownTo undoes migrations until target is the newest one applied.
//
// Reverse order, one transaction each, and the row is removed from
// schema_migrations in the same transaction as the reversal it records — so an
// interrupted downgrade leaves the database at a migration boundary rather than
// partway through an unknown one, exactly as the forward path does.
//
// The name is the whole filename, because that is what schema_migrations holds
// and what `cardinal migrate -status` prints. A number would be friendlier and
// would also be a second way to refer to the same thing, which is how the two
// drift.
func (s *Store) MigrateDownTo(ctx context.Context, target string) ([]string, error) {
	applied, err := s.AppliedMigrations(ctx)
	if err != nil {
		return nil, err
	}
	if len(applied) == 0 {
		return nil, nil
	}

	// Everything strictly newer than the target, newest first.
	var undo []string
	found := target == ""
	for i := len(applied) - 1; i >= 0; i-- {
		if applied[i].Name == target {
			found = true
			break
		}
		undo = append(undo, applied[i].Name)
	}
	if !found {
		return nil, fmt.Errorf(
			"store: %q is not an applied migration — `cardinal migrate -status` "+
				"lists what is", target)
	}

	// Every reversal is checked before any of them runs. Stopping halfway
	// because the fourth one turns out to be missing would leave the schema
	// somewhere no version of Cardinal has ever been.
	for _, name := range undo {
		if _, ok := migrations.Down(name); !ok {
			return nil, fmt.Errorf("%w: %s — nothing was changed", ErrIrreversible, name)
		}
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: acquiring connection: %w", err)
	}
	defer conn.Release()

	if _, execErr := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLock); execErr != nil {
		return nil, fmt.Errorf("store: taking migration lock: %w", execErr)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), //nolint:errcheck // the lock is released by the connection dropping regardless
			`SELECT pg_advisory_unlock($1)`, migrationLock)
	}()

	var undone []string
	for _, name := range undo {
		body, _ := migrations.Down(name)
		err := s.InTx(ctx, func(tx pgx.Tx) error {
			if _, execErr := tx.Exec(ctx, string(body)); execErr != nil {
				return fmt.Errorf("reversing %s: %w", name, execErr)
			}
			_, execErr := tx.Exec(ctx,
				`DELETE FROM schema_migrations WHERE name = $1`, name)
			return execErr
		})
		if err != nil {
			return undone, fmt.Errorf("store: %w", err)
		}
		undone = append(undone, name)
	}
	return undone, nil
}
