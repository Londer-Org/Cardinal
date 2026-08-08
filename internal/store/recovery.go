package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.londer.be/cardinal/internal/event"
	"golang.org/x/crypto/argon2"
)

// RecoveryCodeCount is how many codes are issued at once. Enough that losing a
// few is survivable, few enough that nobody is tempted to store them
// electronically "just for now".
const RecoveryCodeCount = 10

// Recovery codes are 20 base32 characters ~ 100 bits of entropy. Far beyond
// guessable, and still short enough to read off paper without errors.
const recoveryCodeBytes = 13

// Argon2id parameters. Recovery codes have ~100 bits of entropy so they are not
// realistically guessable offline, but they are the credential of last resort
// and are stored for years — a slow hash costs nothing here, since verification
// happens at most a handful of times per account, ever.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
)

var (
	ErrNoRecoveryCode  = errors.New("store: recovery code not recognised")
	ErrCodeAlreadyUsed = errors.New("store: recovery code already used")
)

// GenerateRecoveryCodes issues a fresh set, replacing any that remain unused.
//
// Returns the plaintext codes exactly once. They are never recoverable
// afterwards: only Argon2id hashes are stored, for the same reason a password
// would be, so reading the database yields nothing usable.
func (s *Store) GenerateRecoveryCodes(ctx context.Context, entityID uuid.UUID, actorID *uuid.UUID) ([]string, error) {
	codes := make([]string, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}

	err := s.InTx(ctx, func(tx pgx.Tx) error {
		// Replace rather than accumulate: leaving old codes valid would mean a
		// set printed years ago still works, long after anyone remembers where
		// it went.
		if _, err := tx.Exec(ctx,
			`DELETE FROM recovery_codes WHERE entity_id = $1 AND used_at IS NULL`,
			entityID); err != nil {
			return fmt.Errorf("store: clearing recovery codes: %w", err)
		}

		for _, code := range codes {
			salt, hash := hashRecoveryCode(entityID, code)
			if _, err := tx.Exec(ctx,
				`INSERT INTO recovery_codes (entity_id, code_hash) VALUES ($1, $2)`,
				entityID, append(salt, hash...)); err != nil {
				return fmt.Errorf("store: storing recovery code: %w", err)
			}
		}

		ev, err := event.New(event.ActionRecoveryCodesIssued, &entityID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// RedeemRecoveryCode consumes a code if it is valid and unused.
//
// Every stored code for the account is checked, because the salt differs per
// code and there is no way to look one up directly. That is intentional: the
// alternative is a deterministic hash, which would let anyone with database
// access test candidate codes offline against a rainbow table.
func (s *Store) RedeemRecoveryCode(ctx context.Context, entityID uuid.UUID, code string) error {
	code = normaliseRecoveryCode(code)

	return s.InTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, code_hash, used_at IS NOT NULL
			   FROM recovery_codes WHERE entity_id = $1`, entityID)
		if err != nil {
			return fmt.Errorf("store: reading recovery codes: %w", err)
		}

		type candidate struct {
			id   uuid.UUID
			hash []byte
			used bool
		}
		var candidates []candidate
		for rows.Next() {
			var c candidate
			if err := rows.Scan(&c.id, &c.hash, &c.used); err != nil {
				rows.Close()
				return fmt.Errorf("store: scanning recovery code: %w", err)
			}
			candidates = append(candidates, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Every candidate is checked even after a match, so the time taken does
		// not reveal how many codes remain or which one matched.
		var (
			matched     *candidate
			matchedUsed bool
		)
		for i := range candidates {
			c := candidates[i]
			if len(c.hash) < 16 {
				continue
			}
			salt, want := c.hash[:16], c.hash[16:]
			got := argon2.IDKey(recoveryCodeInput(entityID, code), salt,
				argonTime, argonMemory, argonThreads, argonKeyLen)
			if ConstantTimeCompare(got, want) && matched == nil {
				matched = &candidates[i]
				matchedUsed = c.used
			}
		}

		switch {
		case matched == nil:
			return ErrNoRecoveryCode
		case matchedUsed:
			return ErrCodeAlreadyUsed
		}

		tag, err := tx.Exec(ctx,
			`UPDATE recovery_codes SET used_at = now()
			  WHERE id = $1 AND used_at IS NULL`, matched.id)
		if err != nil {
			return fmt.Errorf("store: consuming recovery code: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Lost a race with a concurrent redemption of the same code.
			return ErrCodeAlreadyUsed
		}

		ev, err := event.New(event.ActionRecoveryCodeUsed, &entityID, &entityID,
			map[string]any{"auth_method": "recovery_code"})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// RemainingRecoveryCodes reports how many are still unused, so the UI can nag
// before someone runs out entirely.
func (s *Store) RemainingRecoveryCodes(ctx context.Context, entityID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_codes WHERE entity_id = $1 AND used_at IS NULL`,
		entityID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: counting recovery codes: %w", err)
	}
	return n, nil
}

func newRecoveryCode() (string, error) {
	raw := make([]byte, recoveryCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: generating recovery code: %w", err)
	}
	// Crockford-style alphabet: no I, L, O or U, so codes cannot be misread off
	// paper and cannot accidentally spell anything.
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	var b strings.Builder
	for i, v := range raw {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(alphabet[int(v)%len(alphabet)])
		b.WriteByte(alphabet[int(v>>5)%len(alphabet)])
	}
	return b.String(), nil
}

// normaliseRecoveryCode makes transcription forgiving: case and grouping
// hyphens are irrelevant, since someone typing a code off paper during an
// incident should not be defeated by formatting.
func normaliseRecoveryCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
}

// recoveryCodeInput binds the code to its account, so a code stolen from one
// account's row cannot be replayed against another.
func recoveryCodeInput(entityID uuid.UUID, code string) []byte {
	return append(entityID[:], []byte(normaliseRecoveryCode(code))...)
}

func hashRecoveryCode(entityID uuid.UUID, code string) (salt, hash []byte) {
	salt = make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		// crypto/rand failing means the system is unusable for anything
		// security-related; continuing would silently weaken every code.
		panic(fmt.Sprintf("store: crypto/rand unavailable: %v", err))
	}
	hash = argon2.IDKey(recoveryCodeInput(entityID, code), salt,
		argonTime, argonMemory, argonThreads, argonKeyLen)
	return salt, hash
}
