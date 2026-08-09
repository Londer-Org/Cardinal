// Package store is Cardinal's PostgreSQL persistence layer.
//
// PostgreSQL is the only datastore: sessions, queues, pub/sub and search all
// live here. See docs/adr/0004-postgresql-is-the-only-datastore.md.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// minServerVersion is PostgreSQL 19. The temporal model uses FOR PORTION OF,
// which does not exist before it, and we deliberately shipped no fallback:
// PG19 GA was weeks away when this was written, so a dual-path implementation
// would have been written only to be deleted.
const minServerVersion = 190000

// Store owns the connection pool.
type Store struct {
	pool *pgxpool.Pool

	// limits bound session lifetime. Zero means the defaults, so a Store opened
	// without them is usable rather than issuing sessions that never expire.
	limits SessionLimits
}

// SetSessionLimits applies the configured session clocks.
//
// Set after Open rather than passed to it, because the DSN is available long
// before the configuration is — `cardinal migrate` opens a store with neither.
func (s *Store) SetSessionLimits(limits SessionLimits) {
	s.limits = limits.withDefaults()
}

func (s *Store) sessionLimits() SessionLimits { return s.limits.withDefaults() }

// PoolLimits bound the connection pool.
//
// Separate from SessionLimits and applied at Open rather than after it, because
// a pgxpool's size is fixed once the pool is built. A zero field means "leave
// pgx's own default", which is what `cardinal migrate` and the CLI get: they
// have a DSN long before they have a configuration file, and a one-shot command
// has no opinion about pool sizing.
type PoolLimits struct {
	MaxConns        int
	ConnMaxLifetime time.Duration
}

// Open connects with pgx's own pool defaults.
func Open(ctx context.Context, dsn string) (*Store, error) {
	return OpenWithLimits(ctx, dsn, PoolLimits{})
}

// OpenWithLimits connects, verifies the server is new enough, and returns a
// Store whose pool is bounded as configured.
//
// These settings were parsed and never reached the pool for two releases, so an
// operator tuning a busy deployment silently got pgx's defaults — max(4, NumCPU)
// connections, measured, and an hour's lifetime — while the configuration page
// showed the number they had chosen.
func OpenWithLimits(ctx context.Context, dsn string, limits PoolLimits) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parsing dsn: %w", err)
	}

	// Applied only where the connection string is silent. pgx reads
	// pool_max_conns and pool_max_conn_lifetime from the DSN itself, and
	// overriding one somebody wrote there would replace a setting that works
	// with one that looks like it does — which is the bug being fixed here,
	// moved rather than removed.
	if limits.MaxConns > 0 && !strings.Contains(dsn, "pool_max_conns") {
		cfg.MaxConns = int32(limits.MaxConns) //nolint:gosec // Config.Validate refuses anything outside 0..500
	}
	if limits.ConnMaxLifetime > 0 && !strings.Contains(dsn, "pool_max_conn_lifetime") {
		cfg.MaxConnLifetime = limits.ConnMaxLifetime
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connecting: %w", err)
	}

	s := &Store{pool: pool}
	if err := s.checkVersion(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// checkVersion fails fast at startup rather than letting the first temporal
// write fail with a confusing syntax error at 3am.
func (s *Store) checkVersion(ctx context.Context) error {
	// current_setting(...)::int rather than SHOW: SHOW returns text, which the
	// driver will not scan into an int.
	var num int
	err := s.pool.QueryRow(ctx,
		`SELECT current_setting('server_version_num')::int`).Scan(&num)
	if err != nil {
		return fmt.Errorf("store: reading server version: %w", err)
	}
	if num < minServerVersion {
		return fmt.Errorf(
			"store: PostgreSQL 19 or newer required (server reports %d); "+
				"the temporal access model depends on FOR PORTION OF", num)
	}
	return nil
}

// Pool exposes the underlying connection pool, for callers that need to run a
// statement this package does not wrap.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Close releases the connection pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks the database is reachable.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// InTx runs fn inside a transaction, rolling back on error or panic.
//
// Most of Cardinal's writes are multi-statement by necessity: a state change
// and its audit event must commit together, or the journal drifts from reality
// (ADR 0003). This helper is how that invariant is kept.
func (s *Store) InTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: beginning transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			// Best-effort rollback, then re-panic: swallowing it here would
			// turn a bug into a silently half-applied write.
			_ = tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // a rollback after a successful commit returns ErrTxClosed
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		// context.WithoutCancel so the rollback still runs when the failure was
		// the context expiring. Otherwise the transaction lingers until the
		// connection is reaped.
		if rbErr := tx.Rollback(context.WithoutCancel(ctx)); rbErr != nil &&
			!errors.Is(rbErr, pgx.ErrTxClosed) {
			return errors.Join(err, fmt.Errorf("store: rollback failed: %w", rbErr))
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: committing: %w", err)
	}
	return nil
}

// PostgreSQL error codes we translate into domain errors.
const (
	codeUniqueViolation     = "23505"
	codeExclusionViolation  = "23P01"
	codeForeignKeyViolation = "23503"
)

// pgErrCode extracts the SQLSTATE code, or "" if err is not a PostgreSQL error.
func pgErrCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// constraintName reports which constraint was violated, so callers can tell an
// overlapping-grant conflict from a self-membership one.
func constraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}
