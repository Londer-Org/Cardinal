// Package temporal models time-bounded access.
//
// Every grant in Cardinal carries a validity period that the database enforces,
// so expiry is a property of the data rather than of a scheduled job that might
// not run. See docs/adr/0001-temporal-access-model.md.
package temporal

import (
	"errors"
	"fmt"
	"time"
)

// Period is a half-open interval [From, Until): From is included, Until is not.
//
// Half-open matches PostgreSQL's default tstzrange bounds and, more usefully,
// makes adjacent periods meet exactly without overlapping — so revoking at
// noon and re-granting at noon leaves no gap and triggers no conflict.
type Period struct {
	From time.Time

	// Until nil means "no end" — the grant continues indefinitely. It is
	// stored as PostgreSQL's 'infinity', not NULL, so range operators behave
	// consistently.
	Until *time.Time
}

var (
	ErrEmptyPeriod   = errors.New("temporal: period is empty")
	ErrInvertedRange = errors.New("temporal: period ends before it starts")
)

// Forever returns a period starting now with no end.
func Forever() Period {
	return Period{From: time.Now().UTC().Truncate(time.Microsecond)}
}

// From returns an open-ended period starting at t.
func FromTime(t time.Time) Period {
	return Period{From: t.UTC().Truncate(time.Microsecond)}
}

// Between returns a bounded period. It is the shape most access grants should
// take: someone asking for access almost always knows when they no longer need
// it, and a bounded grant cannot be forgotten.
func Between(from, until time.Time) Period {
	u := until.UTC().Truncate(time.Microsecond)
	return Period{From: from.UTC().Truncate(time.Microsecond), Until: &u}
}

// For returns a period starting now and lasting d.
func For(d time.Duration) Period {
	return Between(time.Now(), time.Now().Add(d))
}

// Validate rejects periods the database would reject anyway, so the error
// arrives with useful context instead of as a constraint violation.
func (p Period) Validate() error {
	if p.Until == nil {
		return nil
	}
	switch {
	case p.Until.Before(p.From):
		return fmt.Errorf("%w: %s to %s", ErrInvertedRange,
			p.From.Format(time.RFC3339), p.Until.Format(time.RFC3339))
	case p.Until.Equal(p.From):
		// Half-open means [t, t) contains no instant at all. Postgres would
		// reject this via the isempty() check constraint.
		return fmt.Errorf("%w: %s to %s (zero-length)", ErrEmptyPeriod,
			p.From.Format(time.RFC3339), p.Until.Format(time.RFC3339))
	}
	return nil
}

// Contains reports whether t falls inside the period.
func (p Period) Contains(t time.Time) bool {
	if t.Before(p.From) {
		return false
	}
	return p.Until == nil || t.Before(*p.Until)
}

// ActiveAt is Contains, named for how it reads at call sites asking whether a
// grant was live at some instant.
func (p Period) ActiveAt(t time.Time) bool { return p.Contains(t) }

// Active reports whether the period includes the present moment.
func (p Period) Active() bool { return p.Contains(time.Now()) }

func (p Period) String() string {
	if p.Until == nil {
		return fmt.Sprintf("[%s, ∞)", p.From.Format(time.RFC3339))
	}
	return fmt.Sprintf("[%s, %s)",
		p.From.Format(time.RFC3339), p.Until.Format(time.RFC3339))
}
