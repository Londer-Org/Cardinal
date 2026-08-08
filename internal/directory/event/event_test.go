package event

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

// TestLengthPrefixingPreventsCollisions is the reason ComputeHash prefixes each
// field with its length rather than simply concatenating.
//
// With naive concatenation, ("ab", "c") and ("a", "bc") produce identical hash
// input. An attacker able to influence two adjacent fields could then craft two
// semantically different events with the same hash and substitute one for the
// other without breaking the chain — defeating the entire point of the journal.
//
// Here the boundary is moved between action and payload: the encoding must
// distinguish them.
func TestLengthPrefixingPreventsCollisions(t *testing.T) {
	id := uuid.MustParse("019fd328-5f31-7276-9d56-7166e24c0c31")

	a := &Event{ID: id, Action: "entity.create", Payload: map[string]any{"k": "dX"}}
	b := &Event{ID: id, Action: "entity.createdX", Payload: map[string]any{"k": ""}}

	if err := a.ComputeHash(nil); err != nil {
		t.Fatal(err)
	}
	if err := b.ComputeHash(nil); err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(a.Hash, b.Hash) {
		t.Fatal("distinct events hashed identically — the encoding is ambiguous, " +
			"which would let an attacker swap one event for another undetected")
	}
}

// TestHashIsDeterministic: the same content must always hash the same, or
// previously-valid chains would fail validation for no reason. Map iteration
// order in Go is randomised, so this specifically guards the payload encoding.
func TestHashIsDeterministic(t *testing.T) {
	id := uuid.MustParse("019fd328-5f31-7276-9d56-7166e24c0c31")
	payload := map[string]any{"z": 1, "a": 2, "m": 3, "b": 4, "y": 5}

	first := &Event{ID: id, Action: "entity.created", Payload: payload}
	if err := first.ComputeHash(nil); err != nil {
		t.Fatal(err)
	}

	// Recompute many times: if key ordering leaked into the encoding, Go's
	// randomised map iteration would surface it within a few attempts.
	for range 50 {
		again := &Event{ID: id, Action: "entity.created", Payload: payload}
		if err := again.ComputeHash(nil); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Hash, again.Hash) {
			t.Fatal("hash is not deterministic — map iteration order is leaking " +
				"into the encoding, which would break validation of existing chains")
		}
	}
}

// TestPredecessorChanges: an event's hash must depend on its predecessor, or
// records could be reordered freely.
func TestPredecessorChanges(t *testing.T) {
	id := uuid.MustParse("019fd328-5f31-7276-9d56-7166e24c0c31")

	genesis := &Event{ID: id, Action: "entity.created"}
	if err := genesis.ComputeHash(nil); err != nil {
		t.Fatal(err)
	}

	linked := &Event{ID: id, Action: "entity.created"}
	if err := linked.ComputeHash([]byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(genesis.Hash, linked.Hash) {
		t.Fatal("identical content hashed the same under different predecessors — " +
			"records could be reordered without detection")
	}
}

func TestNewRejectsEmptyAction(t *testing.T) {
	if _, err := New("", nil, nil, nil); err == nil {
		t.Fatal("an event with no action must be rejected")
	}
}

// TestTimestampTruncation: hashes are computed in Go but validated against rows
// read back from PostgreSQL, whose timestamptz resolution is microseconds. A
// nanosecond component would be rounded away by the database and every
// round-tripped event would then fail validation.
func TestTimestampTruncation(t *testing.T) {
	ev, err := New("entity.created", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev.OccurredAt.Nanosecond()%1000 != 0 {
		t.Fatalf("timestamp has sub-microsecond precision (%d ns) that PostgreSQL "+
			"will round away, breaking validation on read-back",
			ev.OccurredAt.Nanosecond())
	}
}
