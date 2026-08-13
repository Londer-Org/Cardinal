package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// Configuring who hears about a revocation, from the console's API.
//
// Streams were a CLI command and nothing else, so whether anybody was
// listening — and whether delivery had been failing for a week — was invisible
// to an operator with a browser. These exercise the endpoints the console
// calls, against the running stack, because the interesting failures are the
// ones a unit test cannot have: the https rule is a CHECK constraint on the
// table rather than code, and the audience is a join through the OIDC client.

const sessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

type consoleStream struct {
	Application string   `json:"application"`
	ClientID    string   `json:"clientId"`
	Endpoint    string   `json:"endpoint"`
	Events      []string `json:"events"`
	Enabled     bool     `json:"enabled"`
}

type consoleStreams struct {
	Streams     []consoleStream `json:"streams"`
	KnownEvents []string        `json:"knownEvents"`
	Pending     int             `json:"pending"`
	Failing     int             `json:"failing"`
	Issuer      string          `json:"issuer"`
	JWKSURI     string          `json:"jwksUri"`
}

// asAdministrator makes the seeded user one, for this test.
//
// Seeded rather than assumed: the suite's user is not an administrator by
// default, and a test that relied on another test having granted it would pass
// or fail depending on the order they ran in. Idempotent, because these tests
// share one database and one another's leftovers.
func asAdministrator(t *testing.T) {
	t.Helper()

	seedSQL(t, `INSERT INTO group_members (group_id, member_id, granted_by, valid_period, reason)
	            SELECT '00000000-0000-7000-8000-00000000ad11', e.id,
	                   '00000000-0000-7000-8000-0000000000d1',
	                   tstzrange(now(), 'infinity'), 'configuring security event streams'
	              FROM entities e WHERE e.name = 'e2e-user'
	            ON CONFLICT DO NOTHING`)
}

func listStreams(t *testing.T, c *http.Client) consoleStreams {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/ssf/streams", "application/json")
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing streams returned %d", resp.StatusCode)
	}

	var out consoleStreams
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding streams: %v", err)
	}
	return out
}

// TestTheConsoleCanConfigureAReceiver is the round trip an operator makes.
func TestTheConsoleCanConfigureAReceiver(t *testing.T) {
	asAdministrator(t)

	c := client(t)
	withSession(t, c)
	freshenSession(t)
	csrf := csrfToken(t, c)

	const app = "e2e-client"
	const endpoint = "https://console-check.example/events"

	// Removed first and last: the schema allows one stream per receiver, so a
	// test that assumed none would pass once and fail on every rerun.
	stale := requestWithCSRF(t, c, http.MethodDelete, "/api/ssf/streams/"+app, csrf) //nolint:bodyclose // drain closes it; bodyclose cannot see through the helper
	drain(stale)

	created := requestWithCSRF2(t, c, http.MethodPut, "/api/ssf/streams/"+app, csrf,
		map[string]any{"endpoint": endpoint, "events": []string{sessionRevoked}})
	defer drain(created)
	if created.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(created.Body) //nolint:errcheck // reported by the assertion
		t.Fatalf("creating a stream returned %d: %s", created.StatusCode, body)
	}

	var stream consoleStream
	if err := json.NewDecoder(created.Body).Decode(&stream); err != nil {
		t.Fatalf("decoding the created stream: %v", err)
	}
	if stream.ClientID == "" {
		t.Error("the response carries no client id, which is the audience a " +
			"receiver checks its tokens against")
	}

	found := false
	for _, s := range listStreams(t, c).Streams {
		if s.Application == app {
			found = true
			if s.Endpoint != endpoint {
				t.Errorf("endpoint is %q, want %q", s.Endpoint, endpoint)
			}
			if !s.Enabled {
				t.Error("a stream is delivering when it is created; nothing paused it")
			}
		}
	}
	if !found {
		t.Fatal("the stream was created and does not appear in the list")
	}

	// Pausing rather than deleting is what somebody does when a receiver is
	// down, so the configuration survives the outage.
	paused := requestWithCSRF(t, c, http.MethodPost, "/api/ssf/streams/"+app+"/pause", csrf) //nolint:bodyclose // drain closes it; bodyclose cannot see through the helper
	drain(paused)
	for _, s := range listStreams(t, c).Streams {
		if s.Application == app && s.Enabled {
			t.Error("the stream still reports itself as delivering after being paused")
		}
	}

	resumed := requestWithCSRF(t, c, http.MethodPost, "/api/ssf/streams/"+app+"/resume", csrf) //nolint:bodyclose // drain closes it; bodyclose cannot see through the helper
	drain(resumed)

	removed := requestWithCSRF(t, c, http.MethodDelete, "/api/ssf/streams/"+app, csrf) //nolint:bodyclose // drain closes it; bodyclose cannot see through the helper
	drain(removed)

	for _, s := range listStreams(t, c).Streams {
		if s.Application == app {
			t.Error("the stream is still listed after being removed")
		}
	}
}

// TestTheConsoleRefusesAnUnusableStream covers the answers that have to be
// legible rather than merely correct.
//
// The https rule lives in a CHECK constraint on ssf_streams, so without a
// check in the handler a plain-http endpoint reaches the database and returns
// a constraint violation — a 500 that tells an operator nothing about what
// they typed wrong.
func TestTheConsoleRefusesAnUnusableStream(t *testing.T) {
	asAdministrator(t)

	c := client(t)
	withSession(t, c)
	freshenSession(t)
	csrf := csrfToken(t, c)

	for _, tc := range []struct {
		name string
		path string
		body map[string]any
		want int
	}{
		{
			"a cleartext endpoint", "/api/ssf/streams/e2e-client",
			map[string]any{"endpoint": "http://plain.example/events", "events": []string{sessionRevoked}},
			http.StatusBadRequest,
		},
		{
			"no events at all", "/api/ssf/streams/e2e-client",
			map[string]any{"endpoint": "https://ok.example/events", "events": []string{}},
			http.StatusBadRequest,
		},
		{
			"an event Cardinal does not transmit", "/api/ssf/streams/e2e-client",
			map[string]any{"endpoint": "https://ok.example/events", "events": []string{"invented"}},
			http.StatusBadRequest,
		},
		{
			"an application that does not exist", "/api/ssf/streams/no-such-application",
			map[string]any{"endpoint": "https://ok.example/events", "events": []string{sessionRevoked}},
			http.StatusNotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := requestWithCSRF2(t, c, http.MethodPut, tc.path, csrf, tc.body)
			defer drain(resp)

			if resp.StatusCode != tc.want {
				body, _ := io.ReadAll(resp.Body) //nolint:errcheck // reported by the assertion
				t.Fatalf("returned %d, want %d: %s", resp.StatusCode, tc.want, body)
			}
		})
	}
}

// TestTheConsoleReportsWhatAReceiverNeeds: the issuer and JWKS are the two
// things a receiver author asks for, and the page shows them so nobody has to
// reconstruct them from the public URL by hand.
func TestTheConsoleReportsWhatAReceiverNeeds(t *testing.T) {
	asAdministrator(t)

	c := client(t)
	withSession(t, c)
	freshenSession(t)

	streams := listStreams(t, c)

	if streams.Issuer == "" {
		t.Error("no issuer reported; a receiver checks it against the one it discovered")
	}
	if streams.JWKSURI == "" {
		t.Error("no JWKS URI reported; without it a receiver cannot verify a signature")
	}
	if len(streams.KnownEvents) == 0 {
		t.Error("no event types offered, so the console would present an empty list " +
			"of things to subscribe to")
	}
}

// requestWithCSRF2 is requestWithCSRF with a JSON body.
//
// The existing helper takes no body and postJSON is fixed to POST; this is the
// PUT-shaped hole between them.
func requestWithCSRF2(
	t *testing.T, c *http.Client, method, path, csrf string, body any,
) *http.Response {
	t.Helper()

	req := jsonRequest(t, method, path, csrf, body)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}
