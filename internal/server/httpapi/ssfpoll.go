package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// Poll-based delivery of security events, RFC 8936.
//
// Push asks the receiver to run an HTTPS endpoint Cardinal can reach. That is
// reasonable for a service in the same network and unreasonable otherwise: a
// receiver behind NAT, on a laptop, or inside a CI job has no such address, and
// neither does one whose operator will not open an inbound path to something
// that accepts security events. Polling reverses the direction, and the token
// delivered is byte for byte the one push would have sent.
//
// The exchange is one request. The receiver says how many events it can take
// and which ones it has finished with; the response carries what is waiting and
// whether there is more. Acknowledgement is separate from receipt on purpose —
// a receiver that crashes after reading and before acknowledging is given the
// same events again, which loses nothing.

// maxPollEvents bounds one response.
//
// A receiver asking for everything at once during an incident could otherwise
// be handed thousands of tokens in a single body. The cap is not a limit on
// what it can collect — moreAvailable tells it to come back — only on how much
// arrives per request.
const maxPollEvents = 500

// defaultPollEvents is what a receiver that names no number gets.
const defaultPollEvents = 100

type pollRequest struct {
	// MaxEvents is how many the receiver is willing to take. Absent means "as
	// many as you have", which the cap still bounds.
	MaxEvents *int `json:"maxEvents"`

	// ReturnImmediately false asks the transmitter to wait for an event rather
	// than answer empty. Cardinal always answers immediately; see the note in
	// handlePollEvents.
	ReturnImmediately *bool `json:"returnImmediately"`

	// Ack lists the jti of every event the receiver has processed.
	Ack []string `json:"ack"`

	// SetErrs reports events the receiver could not accept. Read and logged
	// rather than acted on: the specification lets a transmitter decide, and
	// discarding an event because its recipient called it malformed would throw
	// away a revocation on the say-so of the thing being revoked.
	SetErrs map[string]pollSetError `json:"setErrs"`
}

type pollSetError struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

type pollResponse struct {
	// Sets maps jti to the signed token, as RFC 8936 specifies.
	Sets map[string]string `json:"sets"`

	// MoreAvailable tells a receiver whether to poll again at once.
	MoreAvailable bool `json:"moreAvailable"`
}

// handlePollEvents delivers what is queued for the calling receiver.
//
// The caller is authenticated by an access token whose subject is the receiver
// application and which carries the events scope. That pairing is the whole
// authorization: a stream belongs to exactly one receiver, so the events it may
// collect are precisely the ones addressed to it. There is no Cedar action
// here, and that is deliberate rather than an omission — the question policy
// would be asked is "may this receiver have its own events", which the operator
// already answers by enabling or pausing the stream.
func (s *Server) handlePollEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	session, ok := SessionFrom(ctx)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req pollRequest
	// An empty body is a valid poll — "give me what you have, I have finished
	// nothing" — so a decode failure is only reported when there was something
	// to decode.
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	stream, err := s.store.StreamFor(ctx, session.SubjectID)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			// 404 rather than 403: the credential is valid and the caller is
			// who it says it is. What is missing is a stream, and an operator
			// reading this needs to know which of the two to go and fix.
			writeError(w, http.StatusNotFound,
				"no security event stream is configured for this receiver")
			return
		}
		s.log.ErrorContext(ctx, "looking up a stream for polling failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the stream")
		return
	}

	if stream.DeliveryMethod != store.DeliveryPoll {
		writeError(w, http.StatusConflict,
			"this stream is delivered by push, so there is nothing to poll for: "+
				"its events are posted to the endpoint it was configured with")
		return
	}

	// Acknowledged first, so that a receiver acknowledging the previous batch
	// and asking for the next in one request does not get the batch it just
	// finished with handed back to it.
	if len(req.Ack) > 0 {
		jtis, badJTI := parseAcknowledgements(req.Ack)
		if badJTI != "" {
			// The receiver's fault and reported as such. This was a 500 with
			// "could not record the acknowledgement" until it was tried: a
			// message that reads as a Cardinal fault, for a request only the
			// receiver can fix, sends whoever is debugging to the wrong logs.
			writeError(w, http.StatusBadRequest,
				"an acknowledgement carried "+badJTI+", which is not an event "+
					"identifier Cardinal issued: acknowledge the jti each event "+
					"is keyed by in the response")
			return
		}

		acked, ackErr := s.store.AcknowledgeEvents(ctx, stream.ID, jtis)
		if ackErr != nil {
			s.log.ErrorContext(ctx, "acknowledging security events failed", "error", ackErr)
			writeError(w, http.StatusInternalServerError, "could not record the acknowledgement")
			return
		}
		s.log.InfoContext(ctx, "security events acknowledged",
			"receiver", stream.Name, "acknowledged", acked, "claimed", len(req.Ack))
	}

	for jti, setErr := range req.SetErrs {
		// Logged and kept. The receiver says it could not process this one; the
		// event stays queued and is offered again, because the alternative is
		// discarding a revocation because its recipient objected to it.
		s.log.WarnContext(ctx, "a receiver reported a bad security event",
			"receiver", stream.Name, "jti", jti,
			"error", setErr.Err, "description", setErr.Description)
	}

	if stream.Enabled {
		limit := defaultPollEvents
		if req.MaxEvents != nil {
			limit = *req.MaxEvents
		}
		if limit <= 0 || limit > maxPollEvents {
			limit = maxPollEvents
		}

		events, pollErr := s.store.PollEvents(ctx, stream.ID, limit)
		if pollErr != nil {
			s.log.ErrorContext(ctx, "reading queued security events failed", "error", pollErr)
			writeError(w, http.StatusInternalServerError, "could not read what is queued")
			return
		}

		sets := make(map[string]string, len(events))
		for _, e := range events {
			sets[e.JTI.String()] = e.Token
		}

		pending, countErr := s.store.PendingForStream(ctx, stream.ID)
		if countErr != nil {
			// Not fatal. The events in hand are still worth delivering, and a
			// receiver that polls again finds out what is left.
			s.log.ErrorContext(ctx, "counting queued security events failed", "error", countErr)
		}

		writeJSON(w, http.StatusOK, pollResponse{
			Sets:          sets,
			MoreAvailable: pending > len(events),
		})
		return
	}

	// A paused stream answers empty rather than refusing. Pausing is how an
	// operator stops delivery without discarding the configuration, and a
	// receiver polling a paused stream should wait quietly rather than treat it
	// as an error and alert somebody.
	writeJSON(w, http.StatusOK, pollResponse{Sets: map[string]string{}})
}

// parseAcknowledgements converts what the receiver claims into identifiers,
// naming the first value that is not one.
//
// Refused rather than skipped. A receiver sending identifiers Cardinal never
// issued is one whose acknowledgements are not working, and quietly accepting
// them would leave its queue growing while every response looked successful —
// the failure would surface days later as an outbox nothing drains.
func parseAcknowledgements(ack []string) ([]uuid.UUID, string) {
	jtis := make([]uuid.UUID, 0, len(ack))
	for _, raw := range ack {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, strconv.Quote(raw)
		}
		jtis = append(jtis, id)
	}
	return jtis, ""
}
