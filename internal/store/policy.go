package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrNoActivePolicy = errors.New("store: no policy version is active")

// PolicyVersion is an immutable snapshot of the policy set.
type PolicyVersion struct {
	ID          uuid.UUID
	Version     int64
	Document    string
	Digest      []byte
	Description string
	CreatedAt   time.Time
	ActivatedAt *time.Time
}

// Active reports whether this version is the live one.
func (p *PolicyVersion) Active() bool { return p.ActivatedAt != nil }

// PublishPolicy stores a new version without activating it.
//
// Publish and activate are separate so a version can be loaded, inspected, and
// tested against real decisions before it governs anything. Coupling them would
// make every policy change a deployment with no dry run.
func (s *Store) PublishPolicy(ctx context.Context, document, description string, actorID *uuid.UUID) (*PolicyVersion, error) {
	digest := sha256.Sum256([]byte(document))

	v := &PolicyVersion{Document: document, Digest: digest[:], Description: description}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO policy_versions (document, digest, description, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, version, created_at`,
		document, digest[:], description, actorID,
	).Scan(&v.ID, &v.Version, &v.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: publishing policy: %w", err)
	}
	return v, nil
}

// ActivatePolicy makes a version live.
//
// A pointer move, not a rewrite, so rollback is immediate and does not require
// re-uploading anything: activating an older version is the same operation.
//
// The published document itself is frozen by a database trigger, which raises
// if the text, digest, version or creation time changes. Activation only moves
// activated_at, which the trigger deliberately permits — policy text is
// evidence, the live pointer is state.
func (s *Store) ActivatePolicy(ctx context.Context, version int64, actorID *uuid.UUID) error {
	return s.InTx(ctx, func(tx pgx.Tx) error {
		// Exactly one version is live, so the previous pointer clears first.
		// Both statements are in one transaction: a window with no active
		// policy would make every decision fail closed, which is safe but is
		// still an outage.
		if _, err := tx.Exec(ctx,
			`UPDATE policy_versions SET activated_at = NULL WHERE activated_at IS NOT NULL`,
		); err != nil {
			return fmt.Errorf("store: deactivating previous policy: %w", err)
		}

		tag, err := tx.Exec(ctx,
			`UPDATE policy_versions SET activated_at = now() WHERE version = $1`, version)
		if err != nil {
			return fmt.Errorf("store: activating policy: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("store: no policy version %d", version)
		}
		return nil
	})
}

// ActivePolicy returns the live version.
func (s *Store) ActivePolicy(ctx context.Context) (*PolicyVersion, error) {
	var v PolicyVersion
	err := s.pool.QueryRow(ctx, `
		SELECT id, version, document, digest, description, created_at, activated_at
		  FROM policy_versions
		 WHERE activated_at IS NOT NULL
		 ORDER BY activated_at DESC
		 LIMIT 1`,
	).Scan(&v.ID, &v.Version, &v.Document, &v.Digest, &v.Description,
		&v.CreatedAt, &v.ActivatedAt)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoActivePolicy
	}
	if err != nil {
		return nil, fmt.Errorf("store: reading active policy: %w", err)
	}
	return &v, nil
}

// ListPolicyVersions returns published versions, newest first.
func (s *Store) ListPolicyVersions(ctx context.Context, limit int) ([]*PolicyVersion, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, version, document, digest, description, created_at, activated_at
		  FROM policy_versions
		 ORDER BY version DESC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing policy versions: %w", err)
	}
	defer rows.Close()

	var out []*PolicyVersion
	for rows.Next() {
		var v PolicyVersion
		if err := rows.Scan(&v.ID, &v.Version, &v.Document, &v.Digest,
			&v.Description, &v.CreatedAt, &v.ActivatedAt); err != nil {
			return nil, fmt.Errorf("store: scanning policy version: %w", err)
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

// DecisionRecord is one authorization decision, for the log.
type DecisionRecord struct {
	DecisionPoint string
	PrincipalID   *uuid.UUID
	Action        string
	Resource      string
	Allowed       bool
	Reasons       []string
	Errors        []string
	PolicyVersion int64
	Context       map[string]any
	Duration      time.Duration
}

// LogDecision records an authorization outcome.
//
// Deliberately separate from the events journal. That is tamper-evident audit
// of *changes* and is hash-chained, which serialises writers; this is
// high-volume observability of *access*, with its own retention and no chaining.
// Putting decisions in the journal would make every page view take the chain
// lock.
//
// Failures here are returned but must not fail the request: refusing access
// because a log write failed would turn an observability outage into an
// availability one.
func (s *Store) LogDecision(ctx context.Context, d DecisionRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO decisions (decision_point, principal_id, action, resource,
		                       allowed, reasons, errors, policy_version,
		                       context, duration_us)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		d.DecisionPoint, d.PrincipalID, d.Action, d.Resource, d.Allowed,
		d.Reasons, d.Errors, d.PolicyVersion, d.Context,
		d.Duration.Microseconds())
	if err != nil {
		return fmt.Errorf("store: logging decision: %w", err)
	}
	return nil
}

// RecentDecisions returns decisions for the explorer, newest first.
func (s *Store) RecentDecisions(ctx context.Context, principalID *uuid.UUID, deniedOnly bool, limit int) ([]*DecisionRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT decision_point, principal_id, action, resource, allowed,
		       reasons, errors, coalesce(policy_version, 0), context, duration_us
		  FROM decisions
		 WHERE ($1::uuid IS NULL OR principal_id = $1)
		   AND ($2 = false OR NOT allowed)
		 ORDER BY decided_at DESC
		 LIMIT $3`, principalID, deniedOnly, limit)
	if err != nil {
		return nil, fmt.Errorf("store: reading decisions: %w", err)
	}
	defer rows.Close()

	var out []*DecisionRecord
	for rows.Next() {
		var (
			d          DecisionRecord
			durationUS int64
		)
		if err := rows.Scan(&d.DecisionPoint, &d.PrincipalID, &d.Action, &d.Resource,
			&d.Allowed, &d.Reasons, &d.Errors, &d.PolicyVersion, &d.Context,
			&durationUS); err != nil {
			return nil, fmt.Errorf("store: scanning decision: %w", err)
		}
		d.Duration = time.Duration(durationUS) * time.Microsecond
		out = append(out, &d)
	}
	return out, rows.Err()
}
