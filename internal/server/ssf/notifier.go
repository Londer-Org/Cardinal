package ssf

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/store"
)

// Emitting and delivering.
//
// Two halves on purpose. Emitting happens inside the request that revoked the
// session — it must not fail that request, and it must not wait on a receiver
// — so it signs, queues and returns. Delivering happens in its own loop, and is
// where the network lives.

// Notifier queues and delivers security events.
type Notifier struct {
	Store  *store.Store
	Issuer string
	Log    *slog.Logger

	// Keys supplies the signing key. A function rather than a value because the
	// key rotates, and a Notifier holding one from startup would sign with a
	// retired key until the process restarted.
	Keys func(ctx context.Context) (key any, keyID string, err error)

	// Client is the HTTP client used to push. Its own, with a short timeout: a
	// receiver that hangs must not hold a delivery worker while an incident is
	// waiting on the next event in the queue.
	Client *http.Client
}

func (n *Notifier) log() *slog.Logger {
	if n.Log != nil {
		return n.Log
	}
	return slog.Default()
}

func (n *Notifier) client() *http.Client {
	if n.Client != nil {
		return n.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Emit queues one event for every stream that asked for it.
//
// Never returns an error to its caller, and that is the design rather than
// laziness: this is called from inside the act it describes, and refusing to
// revoke a session because a transmitter could not queue a notification would
// turn "tell the applications" into "cannot sign anybody out". A failure here
// is logged loudly and the revocation still happens.
func (n *Notifier) Emit(ctx context.Context, e Event) {
	if n == nil || n.Store == nil {
		return
	}

	streams, err := n.Store.EnabledStreamsFor(ctx, e.Type)
	if err != nil {
		n.log().ErrorContext(ctx, "ssf: could not find streams for an event",
			"event", e.Type, "error", err)
		return
	}
	if len(streams) == 0 {
		return
	}

	rsaKey, keyID, err := n.Keys(ctx)
	if err != nil {
		// Loud, because the consequence is silent otherwise: applications go on
		// believing a revoked session is good and nothing anywhere says why.
		n.log().ErrorContext(ctx, "ssf: no signing key, so receivers will not be told",
			"event", e.Type, "streams", len(streams), "error", err)
		return
	}

	transmitter := Transmitter{Issuer: n.Issuer, KeyID: keyID}
	if err := transmitter.setKey(rsaKey); err != nil {
		n.log().ErrorContext(ctx, "ssf: the signing key is not usable", "error", err)
		return
	}

	var subject *uuid.UUID
	if e.SubjectID != uuid.Nil {
		id := e.SubjectID
		subject = &id
	}

	for _, s := range streams {
		token, signErr := transmitter.Sign(e, s.ClientID)
		if signErr != nil {
			n.log().ErrorContext(ctx, "ssf: signing failed",
				"event", e.Type, "receiver", s.Name, "error", signErr)
			continue
		}
		if queueErr := n.Store.EnqueueEvent(
			ctx, s.ID, subject, e.Type, token,
		); queueErr != nil {
			n.log().ErrorContext(ctx, "ssf: queueing failed",
				"event", e.Type, "receiver", s.Name, "error", queueErr)
		}
	}
}

// Deliver sends what is due, and reports how many went out.
func (n *Notifier) Deliver(ctx context.Context, batch int) (int, error) {
	if n == nil || n.Store == nil {
		return 0, nil
	}

	claimed, err := n.Store.ClaimEvents(ctx, batch)
	if err != nil {
		return 0, err
	}

	sent := 0
	for _, e := range claimed {
		if pushErr := n.push(ctx, e); pushErr != nil {
			n.log().WarnContext(ctx, "ssf: delivery failed, will retry",
				"event", e.Type, "attempts", e.Attempts, "error", pushErr)
			if markErr := n.Store.EventFailed(ctx, e.ID, pushErr.Error()); markErr != nil {
				n.log().ErrorContext(ctx, "ssf: recording a failure failed", "error", markErr)
			}
			continue
		}
		if markErr := n.Store.EventDelivered(ctx, e.ID); markErr != nil {
			// The receiver has it and the row still says otherwise, so it will
			// be sent again. A duplicate is what jti exists for, and is far
			// better than losing a revocation.
			n.log().ErrorContext(ctx, "ssf: recording delivery failed", "error", markErr)
		}
		sent++
	}
	return sent, nil
}

// push POSTs one token, per RFC 8935.
func (n *Notifier) push(ctx context.Context, e store.QueuedEvent) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint,
		bytes.NewReader([]byte(e.Token)))
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	// The media type the specification requires. A receiver checking it rejects
	// application/json, and the rejection reads as a malformed token.
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")

	resp, err := n.client().Do(req)
	if err != nil {
		return fmt.Errorf("posting: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // nothing actionable remains

	// 202 is what RFC 8935 specifies; 200 and 204 are accepted because
	// receivers in the wild return them and refusing would mean retrying
	// forever against something that has the event.
	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusOK, http.StatusNoContent:
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck // best effort, for the message
	return fmt.Errorf("receiver answered %s: %s", resp.Status, bytes.TrimSpace(body))
}

// journalActions map what the directory records to what a receiver is told.
//
// Only acts that change whether somebody may still be trusted. A rename or a
// group grant is real news to an administrator and none of a receiver's
// business — telling applications about every directory change would make this
// a replication feed with a security event's name on it.
var journalActions = map[string]string{
	"session.revoked":       EventSessionRevoked,
	"entity.disabled":       EventSessionRevoked,
	"credential.registered": EventCredentialChange,
	"credential.revoked":    EventCredentialChange,
}

// JournalActions is what Follow reads from the journal.
func JournalActions() []string {
	out := make([]string, 0, len(journalActions))
	for action := range journalActions {
		out = append(out, action)
	}
	return out
}

// Follow reads the journal and queues what receivers should hear about.
//
// Following the journal rather than being called from each handler is the whole
// design, and the reason is a bug this had first: the emission sat in the HTTP
// layer, so `cardinal user disable` on the server changed the directory and
// told nobody. The journal is the one place every path passes through, because
// a state change and its entry commit together (ADR 0003) — so the CLI, the
// API, SCIM and whatever is added next are all covered without any of them
// knowing this exists.
func (n *Notifier) Follow(ctx context.Context, batch int) (int, error) {
	if n == nil || n.Store == nil {
		return 0, nil
	}

	entries, err := n.Store.FollowJournal(ctx, JournalActions(), batch)
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		eventType, interesting := journalActions[entry.Action]
		if !interesting || entry.SubjectID == nil {
			continue
		}
		n.Emit(ctx, Event{
			Type:      eventType,
			SubjectID: *entry.SubjectID,
			Reason:    reasonFor(entry.Action),
			At:        entry.At,
		})

		// An account being disabled is also the strongest possible reduction in
		// how well somebody is authenticated, and a receiver enforcing its own
		// assurance rules acts on that rather than on a session ending.
		if entry.Action == "entity.disabled" {
			n.Emit(ctx, Event{
				Type:      EventAssuranceLevelChange,
				SubjectID: *entry.SubjectID,
				Reason:    reasonFor(entry.Action),
				At:        entry.At,
			})
		}
	}
	return len(entries), nil
}

// reasonFor is what a receiver's log will say.
//
// Deliberately coarse. This crosses a trust boundary into somebody else's
// system, and a directory should not narrate which administrator did what to
// every application it talks to.
func reasonFor(action string) string {
	switch action {
	case "entity.disabled":
		return "the account was disabled"
	case "session.revoked":
		return "a session was revoked"
	case "credential.registered":
		return "a credential was registered"
	case "credential.revoked":
		return "a credential was revoked"
	default:
		return ""
	}
}
