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

	// Added separately because schema_migrations is bookkeeping rather than
	// schema: it is created here, not by a migration, so it cannot be altered by
	// one either. Nullable and defaulted, which is the same rule the migrations
	// themselves now follow — a version that has never heard of this column goes
	// on writing rows without it.
	if _, execErr := conn.Exec(ctx, `
		ALTER TABLE schema_migrations
		ADD COLUMN IF NOT EXISTS breaking text`); execErr != nil {
		return nil, fmt.Errorf("store: recording compatibility: %w", execErr)
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
			// The reason travels into the database, not just the decision.
			// A binary from before this migration existed cannot read the file
			// to find out whether it was safe; it can read the row.
			var breaking *string
			if why, ok := migrations.Breaking(name); ok {
				breaking = &why
			}
			_, execErr := tx.Exec(ctx,
				`INSERT INTO schema_migrations (name, digest, breaking)
				 VALUES ($1, $2, $3)`,
				name, digest, breaking)
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

// ErrSchemaBreaking reports a database carrying a change this binary predates
// and cannot tolerate.
//
// Rare by construction. Migrations are expand-only, so a schema newer than this
// binary is normally fine — which is what makes rolling back a matter of
// deploying the older image and nothing else. This is the declared exception,
// and it is declared in the database by whatever applied it.
var ErrSchemaBreaking = errors.New("store: the database carries a change this version cannot run against")

// SchemaDrift describes a schema newer than this binary.
type SchemaDrift struct {
	// Unknown are applied migrations this build does not contain.
	Unknown []string

	// Blocking are those among them that declared themselves incompatible,
	// mapped to the reason their author gave.
	Blocking map[string]string
}

// SchemaAhead reports what a newer Cardinal has done to this database.
//
// Drift on its own is not a problem and used to be treated as one. Migrations
// only add, so a binary running against a schema a version or two ahead simply
// does not use the new columns — which is precisely the property that makes
// rollback a redeploy. Refusing outright made that impossible and turned every
// rollback into a schema operation.
//
// What does justify refusing is a migration whose author said so. That reason
// was written into the row when it was applied, so a binary that predates the
// migration can still read it.
func (s *Store) SchemaAhead(ctx context.Context) (SchemaDrift, error) {
	known, err := migrations.Up()
	if err != nil {
		return SchemaDrift{}, fmt.Errorf("store: listing migrations: %w", err)
	}
	mine := make(map[string]struct{}, len(known))
	for _, name := range known {
		mine[name] = struct{}{}
	}
	drift := SchemaDrift{Blocking: map[string]string{}}

	// to_regclass rather than a bare SELECT, because a database nobody has
	// migrated yet has no schema_migrations at all — the fresh-install case,
	// where the honest answer is "nothing has been applied, so nothing is ahead"
	// and not a 42P01 that reads like the database is broken.
	var exists bool
	if scanErr := s.pool.QueryRow(ctx,
		`SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&exists); scanErr != nil {
		return drift, fmt.Errorf("store: looking for the migration table: %w", scanErr)
	}
	if !exists {
		return drift, nil
	}

	// `breaking` may not exist yet: a database last touched by a version from
	// before this column was added still has the old three columns, and asking
	// for a fourth would fail on exactly the deployments this check exists to
	// protect.
	var hasColumn bool
	if scanErr := s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		                WHERE table_name = 'schema_migrations'
		                  AND column_name = 'breaking')`).Scan(&hasColumn); scanErr != nil {
		return drift, fmt.Errorf("store: looking for the compatibility column: %w", scanErr)
	}

	query := `SELECT name, NULL::text FROM schema_migrations ORDER BY name`
	if hasColumn {
		query = `SELECT name, breaking FROM schema_migrations ORDER BY name`
	}
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return drift, fmt.Errorf("store: reading applied migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var breaking *string
		if err := rows.Scan(&name, &breaking); err != nil {
			return drift, err
		}
		if _, ok := mine[name]; ok {
			continue
		}
		drift.Unknown = append(drift.Unknown, name)
		if breaking != nil {
			drift.Blocking[name] = *breaking
		}
	}
	return drift, rows.Err()
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
