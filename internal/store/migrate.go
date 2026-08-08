package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"

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
	entries, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("store: listing migrations: %w", err)
	}
	sort.Strings(entries)

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
