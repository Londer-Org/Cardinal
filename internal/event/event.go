// Package event implements Cardinal's tamper-evident audit journal.
//
// Every mutation appends here in the same transaction as the state change, and
// each record carries the SHA-256 hash of its predecessor. Editing or removing
// any record breaks the chain from that point onward, and Validate detects it.
//
// State tables remain authoritative; this is an audit record, not the source of
// truth. See docs/adr/0003-hash-chained-event-log.md.
package event

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Action names follow "<subject>.<verb>" in past or imperative form. They are
// part of the audit contract: once written they appear in stored hashes
// forever, so renaming one rewrites history and is not permitted.
const (
	ActionEntityCreated  = "entity.created"
	ActionEntityUpdated  = "entity.updated"
	ActionEntityDisabled = "entity.disabled"
	ActionEntityEnabled  = "entity.enabled"
	ActionEntityRedacted = "entity.redacted"

	ActionMembershipGranted = "membership.granted"
	ActionMembershipRevoked = "membership.revoked"

	ActionSessionCreated = "session.created"
	ActionSessionRevoked = "session.revoked"

	// ActionSessionReauthenticated is a step-up: an existing session re-proved
	// its credential to satisfy a freshness rule. Distinct from session.created
	// so that counting sign-ins stays meaningful.
	ActionSessionReauthenticated = "session.reauthenticated"

	// Nothing emits "breakglass.used" any more (ADR 0014), but journals written
	// before that removal still contain it. The constant is gone; the string
	// must never be reused for anything else, because it appears in hashes that
	// cannot be rewritten.

	ActionCredentialRegistered = "credential.registered"
	ActionCredentialRevoked    = "credential.revoked"

	// Access tokens. Issuing one creates a credential that can act as the
	// subject without a passkey, so it is as auditable as registering a
	// credential — which is what it is.
	ActionAccessTokenIssued  = "access_token.issued"
	ActionAccessTokenRevoked = "access_token.revoked"

	ActionRecoveryCodesIssued = "recovery.codes_issued"
	ActionRecoveryCodeUsed    = "recovery.code_used"

	ActionConsentGranted = "consent.granted"
	ActionConsentRevoked = "consent.revoked"

	// Enrollment invitations. Issue and redemption are separate actions rather
	// than one with a status, because "an invitation was issued for this
	// account" and "someone used it" are different facts with different
	// actors, and alerting on the second is not the same as alerting on the
	// first.
	ActionInvitationIssued   = "invitation.issued"
	ActionInvitationRedeemed = "invitation.redeemed"
	ActionInvitationRevoked  = "invitation.revoked"

	// Dual-control recovery. Each step is its own action: alerting on "someone
	// asked to take over an account" is a different question from "a second
	// administrator agreed", and the second is the one that matters.
	ActionRecoveryRequested = "recovery.requested"
	ActionRecoveryApproved  = "recovery.approved"
	ActionRecoveryCancelled = "recovery.cancelled"
)

// Event is one immutable record in the journal.
type Event struct {
	// Seq is assigned by the database and is only meaningful for ordering
	// reads. It deliberately does not participate in the hash: it is not known
	// until INSERT, and prev_hash already establishes the chain order.
	Seq int64

	// ID is a client-generated UUIDv7, so it is unique and time-ordered, and is
	// known before the row exists. It is part of the hash.
	ID uuid.UUID

	OccurredAt time.Time
	Action     string

	// EntityID is what the event is about; ActorID is who caused it. Both are
	// optional: system-initiated events have no actor, and some events concern
	// no single entity.
	EntityID *uuid.UUID
	ActorID  *uuid.UUID

	// Payload carries event-specific detail.
	//
	// It may contain only identifiers, timestamps, booleans and registered
	// enumerations — never personal data or free-form text. This is enforced
	// by validatePayload, not left to convention, because the journal is
	// append-only: anything written here cannot later be deleted to satisfy an
	// erasure request. See ADR 0010 and payload.go.
	Payload map[string]any

	PrevHash []byte
	Hash     []byte
}

// New builds an unhashed Event. Call ComputeHash once the predecessor is known.
func New(action string, entityID, actorID *uuid.UUID, payload map[string]any) (*Event, error) {
	if action == "" {
		return nil, fmt.Errorf("event: action must not be empty")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("event: generating id: %w", err)
	}
	if payload == nil {
		payload = map[string]any{}
	}
	// Fail here rather than writing an unsafe record. Once an event is in the
	// chain it cannot be deleted, so this is the last point at which a
	// personal-data mistake is still cheap to fix.
	if err := validatePayload(payload); err != nil {
		return nil, err
	}
	return &Event{
		ID: id,
		// Truncated to microseconds because that is PostgreSQL timestamptz's
		// resolution. Without this, the hash computed in Go would cover a
		// nanosecond value the database rounds away, and re-validating a row
		// read back from Postgres would fail.
		OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		Action:     action,
		EntityID:   entityID,
		ActorID:    actorID,
		Payload:    payload,
	}, nil
}

// ComputeHash derives this event's hash from its content and its predecessor's.
// Passing nil prev marks a genesis event.
//
// The encoding is length-prefixed, which matters more than it looks. Naive
// concatenation is ambiguous: ("ab","c") and ("a","bc") would produce identical
// input, so an attacker could craft two different events with the same hash and
// swap one for the other without breaking the chain. Prefixing every field with
// its length makes the encoding injective and removes that class of attack.
func (e *Event) ComputeHash(prev []byte) error {
	h := sha256.New()

	writeField := func(b []byte) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(b)))
		h.Write(lenBuf[:])
		h.Write(b)
	}

	writeField(prev)
	writeField(e.ID[:])

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(e.OccurredAt.UnixMicro()))
	writeField(tsBuf[:])

	writeField([]byte(e.Action))
	writeField(optionalUUID(e.EntityID))
	writeField(optionalUUID(e.ActorID))

	// json.Marshal sorts map keys, so the encoding is stable across runs and
	// across Go versions. That stability is load-bearing: an unstable encoding
	// would make previously-valid chains fail validation after an upgrade.
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("event: marshalling payload: %w", err)
	}
	writeField(payload)

	e.PrevHash = prev
	e.Hash = h.Sum(nil)
	return nil
}

func optionalUUID(id *uuid.UUID) []byte {
	if id == nil {
		return nil
	}
	return id[:]
}
