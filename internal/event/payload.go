package event

import (
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// This file enforces ADR 0010: personal data never enters the audit journal.
//
// The journal is append-only and hash-chained, so a row containing someone's
// name cannot later be deleted to satisfy an erasure request. The only durable
// answer is to keep personal data out entirely, and the only reliable way to
// do that is to make unsafe payloads fail rather than trusting every future
// contributor to remember.
//
// Nobody writes payload["email"] = x. They write a "reason" field, and six
// months later it says "covering for Jan while he's on sick leave".

// allowedPayloadKeys is the complete set of keys permitted in an event payload.
//
// Adding a key here is a decision with the same weight as ADR 0010 itself:
// once an event carrying it is written, that data is in the chain permanently.
// A key belongs here only if it can never identify a person.
var allowedPayloadKeys = []string{
	// Opaque identifiers. Redacting the referenced entity severs the link to a
	// person, which is what makes erasure possible without touching the chain.
	"entity_id",
	"group_id",
	"member_id",
	"session_id",

	// Validity periods. Not identifying.
	"from",
	"until",
	"revoked_at",

	// Closed vocabularies. Safe because they cannot carry arbitrary text.
	"type",        // entity type
	"auth_method", // how the subject authenticated

	// Non-identifying scalars.
	"device_bound",
	"depth",

	// Which fields a profile update touched, never their values. Booleans
	// rather than a list of names because slices are rejected outright, and
	// because a boolean cannot smuggle anything: "the display name changed" is
	// the whole fact, and the new value is in the entities table where erasure
	// can reach it.
	"display_name_changed",
	"email_changed",
}

// deniedPayloadKeys are rejected with a pointed message. They would be caught
// by the allowlist anyway, but a generic "key not allowed" invites someone to
// simply add the key; naming the reason invites them to reconsider.
var deniedPayloadKeys = map[string]string{
	"name":         "a username identifies a person; reference entity_id instead",
	"display_name": "a display name identifies a person; reference entity_id instead",
	"email":        "an email address identifies a person; reference entity_id instead",
	"reason":       "free text reliably ends up containing personal data; it belongs in group_members.reason, which is redactable",
	"user_agent":   "user agents are identifying and belong in sessions, which is deletable",
	"ip":           "IP addresses are personal data under GDPR; they belong in sessions",
	"client_ip":    "IP addresses are personal data under GDPR; they belong in sessions",
	"comment":      "free text reliably ends up containing personal data",
	"description":  "free text reliably ends up containing personal data",
	"note":         "free text reliably ends up containing personal data",
}

// ErrUnsafePayload means a payload would have put personal data, or data that
// tends to attract it, into the append-only journal.
type ErrUnsafePayload struct {
	Key    string
	Reason string
}

func (e *ErrUnsafePayload) Error() string {
	return fmt.Sprintf("event: payload key %q is not permitted: %s (see ADR 0010)",
		e.Key, e.Reason)
}

// validatePayload rejects anything that could carry personal data.
//
// Both the key and the value type are checked. The value check is what stops
// an allowed key from smuggling text through: "type" must be a known
// enumeration, never an arbitrary string.
func validatePayload(p map[string]any) error {
	for key, value := range p {
		if reason, denied := deniedPayloadKeys[key]; denied {
			return &ErrUnsafePayload{Key: key, Reason: reason}
		}
		if !slices.Contains(allowedPayloadKeys, key) {
			return &ErrUnsafePayload{
				Key: key,
				Reason: "not in the payload allowlist; if it genuinely cannot identify " +
					"a person, add it to allowedPayloadKeys deliberately",
			}
		}
		if err := validatePayloadValue(key, value); err != nil {
			return err
		}
	}
	return nil
}

// enumPayloadValues constrains the string-valued keys to fixed vocabularies.
// Without this, "type" would be an unchecked string and the allowlist would be
// trivially bypassable.
var enumPayloadValues = map[string][]string{
	"type": {
		"user", "group", "host", "service_account",
		"application", "device", "role",
	},
	"auth_method": {
		"passkey", "totp", "recovery_code", "break_glass", "bootstrap",
	},
}

func validatePayloadValue(key string, value any) error {
	switch v := value.(type) {
	case nil, bool, int, int64, float64, time.Time, uuid.UUID:
		return nil

	case *time.Time:
		return nil

	case string:
		allowed, isEnum := enumPayloadValues[key]
		if !isEnum {
			return &ErrUnsafePayload{
				Key: key,
				Reason: "free-form strings are never permitted in payloads; " +
					"use an identifier or a registered enumeration",
			}
		}
		if !slices.Contains(allowed, v) {
			return &ErrUnsafePayload{
				Key:    key,
				Reason: fmt.Sprintf("%q is not a recognised value for this key", v),
			}
		}
		return nil

	default:
		// Maps and slices are rejected because their contents cannot be
		// checked recursively with any confidence, and nesting is exactly
		// where unreviewed data hides.
		return &ErrUnsafePayload{
			Key:    key,
			Reason: fmt.Sprintf("values of type %T are not permitted; use identifiers, timestamps, booleans or registered enumerations", value),
		}
	}
}
