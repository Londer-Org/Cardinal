package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Collecting security events instead of being pushed them, RFC 8936.
//
// Against the running stack because the interesting parts are not in any one
// package: the event has to travel from a directory change through the journal
// follower into the outbox, and then out through an endpoint authenticated by a
// token issued to an application rather than a person. A unit test can have any
// of those and not the seam between them.

// pollResponseBody is what the endpoint answers.
type pollResponseBody struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

// pollingReceiver configures an application to be polled and returns a
// credential for it.
//
// Both halves are re-run on every call rather than guarded, because the stack
// outlives a single `go test` run: the stream may already be a poll stream from
// a previous run, and the token from that run is not recoverable.
func pollingReceiver(t *testing.T, application string) string {
	t.Helper()

	cardinalCLI(t, "ssf", "stream", "add", application, "-delivery", "poll")
	cardinalCLI(t, "ssf", "stream", "resume", application)

	out := cardinalCLI(t, "ssf", "token", application)
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "crd_pat_") {
			return field
		}
	}
	t.Fatalf("no polling credential in output: %s", out)
	return ""
}

// queueEvents makes something happen that receivers are told about.
//
// Disabling an account emits two: the session revocation and the assurance
// level change that goes with it. Driven through the CLI rather than by
// inserting rows, because the path being tested starts at a directory change
// and the journal follower is the part most likely to be wrong.
func queueEvents(t *testing.T, login string) {
	t.Helper()

	createFixture(t, "user", login, "Poll probe")
	availabilityFixture(t, "user", login, true)
	availabilityFixture(t, "user", login, false)
}

func poll(t *testing.T, token string, body any) (*http.Response, pollResponseBody) {
	t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(http.MethodPost, origin(hostCardinal)+"/ssf/poll", payload) //nolint:noctx // bounded by client timeout
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client(t).Do(req)
	if err != nil {
		t.Fatalf("polling: %v", err)
	}

	var out pollResponseBody
	if resp.StatusCode == http.StatusOK {
		if decodeErr := json.NewDecoder(resp.Body).Decode(&out); decodeErr != nil {
			t.Fatalf("decoding the poll response: %v", decodeErr)
		}
	}
	return resp, out
}

// waitForEvents polls until something is waiting.
//
// The follower runs on a timer rather than in the request that caused the
// change, so an assertion made immediately after `user disable` is a race the
// test would lose about half the time.
func waitForEvents(t *testing.T, token string) pollResponseBody {
	t.Helper()

	for range 40 {
		resp, body := poll(t, token, map[string]any{"maxEvents": 20})
		drain(resp)
		if len(body.Sets) > 0 {
			return body
		}
		time.Sleep(time.Second)
	}
	t.Fatal("nothing was queued for the receiver; either the journal follower " +
		"stopped emitting or the events are not reaching a poll stream")
	return pollResponseBody{}
}

// TestAReceiverCollectsAndAcknowledgesItsEvents is the round trip.
func TestAReceiverCollectsAndAcknowledgesItsEvents(t *testing.T) {
	token := pollingReceiver(t, "e2e-client")

	// Whatever an earlier run left, so the counts below are about this test.
	drainQueue(t, token)

	queueEvents(t, "poll-probe-collect")
	collected := waitForEvents(t, token)

	// The token is the one push would have sent, and it has to be verifiable by
	// a receiver that knows only the OIDC issuer and its own client id.
	for jti, token := range collected.Sets {
		claims := claimsOf(t, token)
		if claims["jti"] != jti {
			t.Errorf("the response is keyed by %q and the token says %q; a receiver "+
				"acknowledging what it was handed would clear the wrong event",
				jti, claims["jti"])
		}
		if claims["aud"] == "" {
			t.Error("no audience, so a receiver cannot tell a token meant for it " +
				"from one replayed from another receiver")
		}
	}

	// Acknowledgement is separate from receipt: polling twice without
	// acknowledging returns the same events, because a receiver that crashed
	// before processing them must not lose them.
	resp, again := poll(t, token, map[string]any{})
	drain(resp)
	if len(again.Sets) != len(collected.Sets) {
		t.Errorf("polling again returned %d events, want the same %d — an "+
			"unacknowledged event must survive being read",
			len(again.Sets), len(collected.Sets))
	}

	acked := make([]string, 0, len(collected.Sets))
	for jti := range collected.Sets {
		acked = append(acked, jti)
	}
	resp, after := poll(t, token, map[string]any{"ack": acked})
	drain(resp)
	if len(after.Sets) != 0 {
		t.Errorf("%d events are still queued after being acknowledged", len(after.Sets))
	}

	// Nothing pushed them. A poll stream has no endpoint, so the delivery loop
	// claiming its events would POST to the empty string, fail, and retry on a
	// backoff for as long as the row exists — while the receiver polls happily
	// and every other assertion here still passes.
	attempted := queryScalar(t, `SELECT count(*) FROM ssf_events e
	    JOIN ssf_streams s ON s.id = e.stream_id
	   WHERE s.delivery_method = 'poll' AND (e.attempts > 0 OR e.last_error IS NOT NULL)`)
	if attempted != "0" {
		t.Errorf("%s of the polled events had delivery attempted against them; "+
			"the push loop is claiming events for a stream that has no endpoint",
			attempted)
	}
}

// TestOneReceiverCannotAcknowledgeAnothersEvents.
//
// The jti arrives in a request body, so without the stream predicate on the
// update a receiver could discard somebody else's events by quoting an
// identifier — and the events discarded would be revocations nobody is told
// about, which fails silently and in the worst possible direction.
func TestOneReceiverCannotAcknowledgeAnothersEvents(t *testing.T) {
	mine := pollingReceiver(t, "e2e-client")
	theirs := pollingReceiver(t, "ssf-receiver")

	drainQueue(t, mine)
	drainQueue(t, theirs)

	queueEvents(t, "poll-probe-crossack")
	victim := waitForEvents(t, theirs)

	stolen := make([]string, 0, len(victim.Sets))
	for jti := range victim.Sets {
		stolen = append(stolen, jti)
	}

	resp, _ := poll(t, mine, map[string]any{"ack": stolen})
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the acknowledgement returned %d", resp.StatusCode)
	}

	resp, still := poll(t, theirs, map[string]any{})
	drain(resp)
	if len(still.Sets) != len(victim.Sets) {
		t.Errorf("the other receiver now has %d of its %d events: one receiver "+
			"acknowledged another's, so those revocations were discarded "+
			"without ever being delivered", len(still.Sets), len(victim.Sets))
	}
}

// TestPollingRefusesWhatItShould covers the answers an operator has to be able
// to act on. Each was wrong when first tried against the stack.
func TestPollingRefusesWhatItShould(t *testing.T) {
	token := pollingReceiver(t, "e2e-client")

	t.Run("no credential", func(t *testing.T) {
		resp, _ := poll(t, "", map[string]any{})
		defer drain(resp)
		// 401 rather than the CSRF refusal this used to give. A receiver has no
		// cookie and no CSRF token, so that answer named a mechanism it does
		// not use and sent whoever read it to the wrong problem.
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("returned %d, want 401", resp.StatusCode)
		}
	})

	t.Run("a credential without the events scope", func(t *testing.T) {
		// Seeds the account the token is issued to; it does not otherwise exist
		// unless the access token tests have already run in this stack.
		adminClient(t)

		wrong := cardinalCLI(t, "token", "create", tokenOwnerLogin,
			"-name", "e2e-poll-wrong-scope", "-for", "1h", "-scope", "identity")
		var bearer string
		for _, field := range strings.Fields(wrong) {
			if strings.HasPrefix(field, "crd_pat_") {
				bearer = field
			}
		}

		resp, _ := poll(t, bearer, map[string]any{})
		defer drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("returned %d, want 403", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // reported by the assertion
		// The remedy has to name a command that exists for this scope. The
		// generic one takes a login, and an events token belongs to an
		// application.
		if !strings.Contains(string(body), "cardinal ssf token") {
			t.Errorf("the refusal does not say how to get a usable credential: %s", body)
		}
	})

	t.Run("an acknowledgement that is not an identifier", func(t *testing.T) {
		resp, _ := poll(t, token, map[string]any{"ack": []string{"not-a-uuid"}})
		defer drain(resp)
		// 400, not 500. This answered "could not record the acknowledgement"
		// with a 500 until it was tried, which reads as a Cardinal fault for a
		// request only the receiver can fix.
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("returned %d, want 400", resp.StatusCode)
		}
	})

	t.Run("a receiver that is pushed to", func(t *testing.T) {
		// The credential is issued while the stream is still polled, then the
		// stream is switched to push underneath it. That is the situation
		// worth covering: a receiver holding a credential that was valid for
		// polling, against a stream that is no longer polled.
		//
		// Nothing restores it, deliberately — pollingReceiver puts it back on
		// every call, and a t.Cleanup here would run after t.Context() is
		// cancelled and could not execute the command at all.
		pushed := pollingReceiver(t, "ssf-receiver")
		cardinalCLI(t, "ssf", "stream", "add", "ssf-receiver",
			"-endpoint", "https://events.cardinal.test:8443/events")

		resp, _ := poll(t, pushed, map[string]any{})
		defer drain(resp)
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("returned %d, want 409 — polling a stream whose events are "+
				"posted elsewhere returns nothing forever, and silence is the "+
				"one answer that looks like working", resp.StatusCode)
		}
	})
}

// queryScalar reads one value from the database.
//
// The e2e suite can seed but could not read, and this assertion needs to see a
// column no API exposes: how many times delivery has been attempted. That
// number is the only evidence of the bug it guards against, because the
// symptom is otherwise invisible — the push loop posting a poll stream's events
// to an empty endpoint fails, leaves them queued, and they stay pollable, so
// every assertion about what a receiver collects passes while Cardinal retries
// forever against nothing.
func queryScalar(t *testing.T, statement string) string {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "docker", "compose",
		"-f", "../../examples/compose.yml",
		"exec", "-T", "postgres", "psql", "-U", "cardinal", "-d", "cardinal",
		"-tAc", statement).CombinedOutput()
	if err != nil {
		t.Fatalf("querying: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// drainQueue acknowledges everything outstanding, so a test counts its own.
func drainQueue(t *testing.T, token string) {
	t.Helper()

	for range 20 {
		resp, body := poll(t, token, map[string]any{"maxEvents": 500})
		drain(resp)
		if len(body.Sets) == 0 {
			return
		}
		jtis := make([]string, 0, len(body.Sets))
		for jti := range body.Sets {
			jtis = append(jtis, jti)
		}
		resp, _ = poll(t, token, map[string]any{"ack": jtis, "maxEvents": 0})
		drain(resp)
	}
}

// claimsOf reads a Security Event Token's payload without verifying it.
//
// The signature is verified by the receiver, and there is a separate test for
// the token's shape. What this is for is checking the envelope the poll
// response wraps it in agrees with what is inside.
func claimsOf(t *testing.T, token string) map[string]string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding the payload: %v", err)
	}

	var claims struct {
		JTI string `json:"jti"`
		Aud string `json:"aud"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("parsing the payload: %v", err)
	}
	return map[string]string{"jti": claims.JTI, "aud": claims.Aud, "iss": claims.Iss}
}

// TestPausingAStreamRecordsNothingNew is the behaviour two comments and a CLI
// message all described backwards.
//
// They said a pause queues events and resuming sends what was missed. It does
// not: `Emit` asks `EnabledStreamsFor`, which filters on the same column
// pausing sets, so a revocation during a pause is never recorded for that
// receiver at all. The receiver goes on honouring the session until its token
// expires, and nothing anywhere says so.
//
// Asserted rather than left to the comment, because a comment is exactly what
// was wrong for as long as this feature has existed.
func TestPausingAStreamRecordsNothingNew(t *testing.T) {
	token := pollingReceiver(t, "e2e-client")
	drainQueue(t, token)

	queued := func() string {
		return queryScalar(t, `SELECT count(*) FROM ssf_events e
		    JOIN ssf_streams s ON s.id = e.stream_id
		    JOIN entities en ON en.id = s.entity_id
		   WHERE en.name = 'e2e-client' AND e.delivered_at IS NULL`)
	}

	// Nothing restores it on failure, and that is deliberate: cardinalCLI runs
	// on t.Context(), which is already cancelled by the time a t.Cleanup would
	// fire, and pollingReceiver resumes the stream on its next call anyway.
	cardinalCLI(t, "ssf", "stream", "pause", "e2e-client")

	before := queued()
	queueEvents(t, "poll-probe-paused")

	// Long enough for the follower, which is what would have queued it.
	time.Sleep(15 * time.Second)

	if after := queued(); after != before {
		t.Errorf("the queue went from %s to %s while the stream was paused. If "+
			"pausing now holds events, the comments and the CLI message that "+
			"say it does not are wrong again — one of the two has to change",
			before, after)
	}

	cardinalCLI(t, "ssf", "stream", "resume", "e2e-client")
	time.Sleep(3 * time.Second)

	if after := queued(); after != before {
		t.Errorf("resuming produced %s queued events from %s: it caught up on the "+
			"pause after all, which is the opposite of what is documented", after, before)
	}
}
