package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/ssf"
)

// Shared Signals streams, from the console.
//
// Deciding which applications are told that a session was revoked is
// administration, and it was the one piece of it that existed only as a CLI
// command. That made it invisible: an operator could not see whether anything
// was listening, whether delivery was failing, or which events a receiver had
// subscribed to — and a transmitter nobody is watching is one that stops
// working quietly, which is the failure mode this whole subsystem exists to
// prevent.
//
// One endpoint returns everything the page needs. An operator asking "is
// anybody receiving revocations, and is it working?" wants both halves, and
// splitting them would mean a page that shows half the answer while the other
// half loads.

type ssfStreamResponse struct {
	// Application is the directory name, which is what the operator knows and
	// what the CLI takes. The client id is shown too because it is the token's
	// audience, and a receiver debugging a rejected token is looking for it.
	Application string `json:"application"`
	ClientID    string `json:"clientId"`

	Endpoint string   `json:"endpoint"`
	Events   []string `json:"events"`
	Enabled  bool     `json:"enabled"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type ssfStreamsResponse struct {
	Streams []ssfStreamResponse `json:"streams"`

	// KnownEvents is what a stream may subscribe to, so the console offers the
	// same set the CLI validates against rather than a copy that can drift.
	KnownEvents []string `json:"knownEvents"`

	// Pending and Failing describe the outbox. Failing is the number that have
	// exhausted their attempts — the only number here that means somebody has
	// to do something.
	Pending int `json:"pending"`
	Failing int `json:"failing"`

	// Transmitter is what a receiver author needs and always asks for: the
	// issuer their tokens will carry, and the JWKS to verify against.
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwksUri"`
}

type ssfStreamRequest struct {
	Endpoint string   `json:"endpoint"`
	Events   []string `json:"events"`
}

// handleListSSFStreams describes every stream and the state of delivery.
func (s *Server) handleListSSFStreams(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	streams, err := s.store.ListStreams(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "listing security event streams failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the streams")
		return
	}

	// A failure to read the outbox is not a failure to describe the streams.
	// The page is still useful without the counts, and refusing the whole
	// response would hide the configuration because a count was unavailable.
	pending, failing, err := s.store.PendingEvents(ctx)
	if err != nil {
		s.log.ErrorContext(ctx, "reading the event outbox failed", "error", err)
	}

	issuer := strings.TrimRight(s.cfg.Server.PublicURL, "/")
	out := ssfStreamsResponse{
		Streams:     make([]ssfStreamResponse, 0, len(streams)),
		KnownEvents: ssf.AllEvents,
		Pending:     pending,
		Failing:     failing,
		Issuer:      issuer,
		JWKSURI:     issuer + "/oidc/keys",
	}
	for _, stream := range streams {
		out.Streams = append(out.Streams, ssfStreamResponse{
			Application: stream.Name,
			ClientID:    stream.ClientID,
			Endpoint:    stream.Endpoint,
			Events:      stream.Events,
			Enabled:     stream.Enabled,
			CreatedAt:   stream.CreatedAt,
			UpdatedAt:   stream.UpdatedAt,
		})
	}

	writeJSON(w, http.StatusOK, out)
}

// handleSaveSSFStream creates or replaces one receiver's stream.
//
// PUT rather than POST: there is exactly one stream per receiver, enforced by
// the schema, so sending it twice is the same request rather than a second
// stream. Two would mean every event delivered twice, and a receiver cannot
// tell a duplicate from a repeat.
func (s *Server) handleSaveSSFStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	var req ssfStreamRequest
	if decodeErr := decodeJSON(r, &req); decodeErr != nil {
		writeError(w, http.StatusBadRequest, decodeErr.Error())
		return
	}

	endpoint := strings.TrimSpace(req.Endpoint)
	if problem := validateStreamEndpoint(endpoint); problem != "" {
		writeError(w, http.StatusBadRequest, problem)
		return
	}

	events, problem := validateStreamEvents(req.Events)
	if problem != "" {
		writeError(w, http.StatusBadRequest, problem)
		return
	}

	app, err := s.store.LookupEntity(ctx, directory.TypeApplication, r.PathValue("application"))
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such application")
			return
		}
		s.log.ErrorContext(ctx, "looking up the receiver failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read that application")
		return
	}

	actorID := session.SubjectID
	stream, err := s.store.SaveStream(ctx, app.ID, endpoint, events, &actorID)
	if err != nil {
		s.log.ErrorContext(ctx, "saving a security event stream failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not save that stream")
		return
	}

	s.log.InfoContext(ctx, "security event stream saved",
		"application", stream.Name, "endpoint", stream.Endpoint,
		"events", len(stream.Events), "actor", session.SubjectID)

	writeJSON(w, http.StatusOK, ssfStreamResponse{
		Application: stream.Name, ClientID: stream.ClientID,
		Endpoint: stream.Endpoint, Events: stream.Events, Enabled: stream.Enabled,
		CreatedAt: stream.CreatedAt, UpdatedAt: stream.UpdatedAt,
	})
}

// handleSetSSFStreamEnabled pauses or resumes delivery.
//
// Pausing rather than deleting is the operation somebody actually wants when a
// receiver is down: the configuration survives, and events stop piling up
// against an endpoint that is refusing them.
func (s *Server) handleSetSSFStreamEnabled(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	// Checked rather than derived from `== "resume"`, so an unrecognised word
	// cannot silently mean pause and report success.
	state := r.PathValue("state")
	if state != "pause" && state != "resume" {
		writeError(w, http.StatusNotFound, "no such action")
		return
	}

	app, ok := s.lookupReceiver(w, r)
	if !ok {
		return
	}

	if err := s.store.SetStreamEnabled(ctx, app.ID, state == "resume"); err != nil {
		s.log.ErrorContext(ctx, "changing a stream's state failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not change that stream")
		return
	}

	s.log.InfoContext(ctx, "security event stream state changed",
		"application", app.Name, "enabled", state == "resume",
		"actor", session.SubjectID)
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteSSFStream stops telling a receiver anything at all.
func (s *Server) handleDeleteSSFStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session, _ := SessionFrom(ctx)

	app, ok := s.lookupReceiver(w, r)
	if !ok {
		return
	}

	if err := s.store.DeleteStream(ctx, app.ID); err != nil {
		s.log.ErrorContext(ctx, "deleting a security event stream failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not remove that stream")
		return
	}

	s.log.InfoContext(ctx, "security event stream removed",
		"application", app.Name, "actor", session.SubjectID)
	w.WriteHeader(http.StatusNoContent)
}

// lookupReceiver resolves the application in the path, or writes the error.
func (s *Server) lookupReceiver(w http.ResponseWriter, r *http.Request) (*directory.Entity, bool) {
	ctx := r.Context()

	app, err := s.store.LookupEntity(ctx, directory.TypeApplication, r.PathValue("application"))
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no such application")
			return nil, false
		}
		s.log.ErrorContext(ctx, "looking up the receiver failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read that application")
		return nil, false
	}
	return app, true
}

// validateStreamEndpoint returns why the endpoint is unusable, or "".
//
// The https rule is a CHECK constraint on ssf_streams, so without this a plain
// http endpoint reaches the database and comes back as a constraint violation —
// a 500 that tells the operator nothing. It is checked here so the answer names
// the problem.
//
// A receiver accepting security events over cleartext is one anybody on the
// path can feed, which is why the rule exists rather than being a preference.
func validateStreamEndpoint(endpoint string) string {
	if endpoint == "" {
		return "an endpoint is required: it is where events are delivered"
	}

	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return "the endpoint must be an absolute URL, such as https://app.example.com/events"
	}
	if parsed.Scheme != "https" {
		return "the endpoint must be https — a receiver accepting security events " +
			"over cleartext is one anybody on the path can feed"
	}
	return ""
}

// validateStreamEvents narrows the requested events, or returns why it cannot.
func validateStreamEvents(requested []string) ([]string, string) {
	events := make([]string, 0, len(requested))
	for _, e := range requested {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !ssf.Valid(e) {
			return nil, e + " is not an event Cardinal transmits"
		}
		events = append(events, e)
	}
	if len(events) == 0 {
		return nil, "choose at least one event: a stream subscribed to nothing receives nothing"
	}
	return events, ""
}
