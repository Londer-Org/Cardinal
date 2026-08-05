// Package store is Cardinal's PostgreSQL persistence layer.
//
// PostgreSQL is the only datastore: sessions, queues, pub/sub and search all
// live here. See docs/adr/0004-postgresql-is-the-only-datastore.md.
package store

import (
	"context"
	"errors"
	"fmt"

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
}

// Open connects, verifies the server is new enough, and returns a Store.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parsing dsn: %w", err)
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

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func (s *Store) Close() { s.pool.Close() }

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
			_ = tx.Rollback(context.WithoutCancel(ctx))
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
