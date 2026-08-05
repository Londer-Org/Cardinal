package event

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestPayloadRejectsPersonalData is the enforcement point for ADR 0010.
//
// The journal is append-only, so a payload containing someone's name can never
// be deleted to satisfy a GDPR erasure request. These cases must fail at
// construction, while the mistake is still one line to fix.
func TestPayloadRejectsPersonalData(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"username", map[string]any{"name": "alonfils"}},
		{"display name", map[string]any{"display_name": "Arthur Lonfils"}},
		{"email", map[string]any{"email": "arthur@example.com"}},
		{"free-text justification", map[string]any{"reason": "covering for Jan while he is off sick"}},
		{"IP address", map[string]any{"client_ip": "192.0.2.10"}},
		{"user agent", map[string]any{"user_agent": "Mozilla/5.0"}},
		{"arbitrary comment", map[string]any{"comment": "see ticket, spoke to his manager"}},

		// The allowlist must be closed. An unknown key could be anything.
		{"unknown key", map[string]any{"employee_number": 1234}},

		// An allowed key must not become a smuggling route for free text.
		{"unregistered enum value", map[string]any{"type": "arthur lonfils"}},

		// Nested structures cannot be checked with confidence, so they are
		// refused outright rather than inspected half-heartedly.
		{"nested map", map[string]any{"entity_id": map[string]any{"name": "alonfils"}}},
		{"slice", map[string]any{"entity_id": []string{"alonfils"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New("entity.created", nil, nil, tc.payload)
			if err == nil {
				t.Fatalf("payload %v was accepted; it would have put personal data "+
					"into an append-only journal that cannot satisfy erasure", tc.payload)
			}
			var unsafe *ErrUnsafePayload
			if !errors.As(err, &unsafe) {
				t.Fatalf("expected ErrUnsafePayload, got %T: %v", err, err)
			}
		})
	}
}

// TestPayloadAcceptsSafeValues: the restriction must still permit everything an
// audit trail legitimately needs, or it will be worked around rather than
// followed.
func TestPayloadAcceptsSafeValues(t *testing.T) {
	until := time.Now().Add(72 * time.Hour)

	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"nil payload", nil},
		{"empty payload", map[string]any{}},
		{"entity reference", map[string]any{"entity_id": uuid.New()}},
		{"grant", map[string]any{
			"group_id": uuid.New(),
			"from":     time.Now(),
			"until":    &until,
		}},
		{"open-ended grant", map[string]any{
			"group_id": uuid.New(),
			"until":    (*time.Time)(nil),
		}},
		{"entity type enum", map[string]any{"type": "service_account"}},
		{"auth method enum", map[string]any{"auth_method": "passkey"}},
		{"booleans and counts", map[string]any{"device_bound": true, "depth": 3}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New("test.action", nil, nil, tc.payload); err != nil {
				t.Fatalf("safe payload rejected: %v", err)
			}
		})
	}
}

// TestDeniedKeysExplainThemselves: a bare "not allowed" invites someone to add
// the key to the allowlist. The message should explain where the data belongs
// instead.
func TestDeniedKeysExplainThemselves(t *testing.T) {
	_, err := New("membership.granted", nil, nil, map[string]any{"reason": "onboarding"})
	if err == nil {
		t.Fatal("expected rejection")
	}
	var unsafe *ErrUnsafePayload
	if !errors.As(err, &unsafe) {
		t.Fatalf("expected ErrUnsafePayload, got %T", err)
	}
	if unsafe.Reason == "" {
		t.Fatal("rejection must explain where the data belongs, not merely refuse")
	}
	t.Logf("message: %s", unsafe)
}
