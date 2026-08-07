package store

import (
	"context"
	"fmt"
	"time"
)

// RateLimit describes an allowance.
type RateLimit struct {
	Scope  string
	Limit  int
	Window time.Duration
}

// Common limits. Authentication endpoints are deliberately tight: they exist to
// bound online guessing, and nobody legitimately begins fifty login ceremonies
// a minute.
var (
	LimitLoginBegin  = RateLimit{Scope: "login:begin", Limit: 20, Window: time.Minute}
	LimitLoginFinish = RateLimit{Scope: "login:finish", Limit: 20, Window: time.Minute}
	LimitRecovery    = RateLimit{Scope: "recovery", Limit: 5, Window: 15 * time.Minute}

	// Enrolling a host is unauthenticated, so this exists — but it is bounding
	// the wrong thing to think of it as anti-guessing. The token is 256 bits and
	// lives an hour; no rate limit is what makes guessing hopeless. What this
	// bounds is unauthenticated work on demand, which does not need to be tight.
	//
	// Deliberately loose, because a tight limit here breaks a real and ordinary
	// case: provisioning a rack of machines behind one NAT means dozens of
	// enrollments from a single address in the same minute, and refusing them
	// looks like Cardinal being broken during exactly the operation somebody is
	// doing for the first time. Found by the end-to-end suite tripping its own
	// limiter at ten per minute.
	LimitHostEnroll = RateLimit{Scope: "host:enroll", Limit: 60, Window: time.Minute}
)

// Deliberately absent: a break-glass limit. The feature was removed in ADR 0014
// and its limit outlived it here, guarding an endpoint that no longer exists —
// exported, so no linter reads it as dead. Rows already written under the old
// scope are left alone; they are a record of what was attempted while it
// existed, and rate_limits is swept by window anyway.

// Allow records an attempt and reports whether it is within the allowance.
//
// A fixed window, which permits up to 2x the limit across a boundary. That
// imprecision is accepted knowingly: this bounds online guessing rather than
// metering anything, and a sliding window costs considerably more to maintain
// for a bound that nobody needs to be exact.
//
// The whole thing is one statement so that concurrent requests cannot both read
// a stale count and both decide they are under the limit.
func (s *Store) Allow(ctx context.Context, limit RateLimit, subject string) (bool, error) {
	windowStart := time.Now().UTC().Truncate(limit.Window)

	var count int
	err := s.pool.QueryRow(ctx, `
		INSERT INTO rate_limits (scope, subject, window_start, count)
		VALUES ($1, $2, $3, 1)
		ON CONFLICT (scope, subject) DO UPDATE
		   SET count = CASE
		           WHEN rate_limits.window_start < EXCLUDED.window_start THEN 1
		           ELSE rate_limits.count + 1
		       END,
		       window_start = GREATEST(rate_limits.window_start, EXCLUDED.window_start)
		RETURNING count`,
		limit.Scope, subject, windowStart,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("store: checking rate limit: %w", err)
	}
	return count <= limit.Limit, nil
}

// PurgeRateLimits clears counters from windows that have passed.
func (s *Store) PurgeRateLimits(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM rate_limits WHERE window_start < now() - $1::interval`,
		olderThan)
	if err != nil {
		return 0, fmt.Errorf("store: purging rate limits: %w", err)
	}
	return tag.RowsAffected(), nil
}
