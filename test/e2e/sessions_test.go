package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// Sessions, through the API their owner reaches.
//
// Nothing could see a session before this. Revocation existed in the store with
// two internal callers — signing out, and disabling an account — so "I think
// somebody else is signed in as me" had no answer, and "am I still signed in on
// the laptop I sold" was unknowable.
//
// The boundary is the same as access tokens and is tested the same way: the
// subject comes from the session on every request, so knowing an identifier
// gets somebody nothing. That matters more here than for a token, because the
// damage is available to anyone who glimpses a UUID — signing a colleague out
// of everything looks exactly like their session expiring, so it would not even
// be reported as an incident.

type liveSession struct {
	ID        string `json:"id"`
	Current   bool   `json:"current"`
	ClientIP  string `json:"clientIp"`
	UserAgent string `json:"userAgent"`
}

func listSessions(t *testing.T, c *http.Client) []liveSession {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/sessions", "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing sessions returned %d", resp.StatusCode)
	}

	var body struct {
		Sessions []liveSession `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Sessions
}

func deleteSession(t *testing.T, c *http.Client, csrf, path string) int {
	t.Helper()

	req, err := http.NewRequest(http.MethodDelete, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Cardinal-CSRF", csrf)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)
	return resp.StatusCode
}

// TestYourOwnSessionIsListedAndMarkedCurrent.
//
// The `current` flag is not decoration. Without it the list is a row of
// near-identical entries and the one session somebody must not end by accident
// — the one they are using — is indistinguishable from the rest.
func TestYourOwnSessionIsListedAndMarkedCurrent(t *testing.T) {
	c, _ := tokenUser(t, "e2e-sessions", "e2e-sessions-session-with-entropy-0123456789abcd")

	sessions := listSessions(t, c)
	if len(sessions) == 0 {
		t.Fatal("no sessions listed while holding one")
	}

	current := 0
	for _, s := range sessions {
		if s.Current {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("%d sessions marked current, want exactly 1", current)
	}
}

// TestOnePersonCannotSeeOrRevokeAnothersSessions.
//
// Both accounts are ordinary users, so nothing passes because of a privilege
// difference. The revocation half matters more than the listing half: a session
// id is a UUID somebody might obtain from a log or a screenshot, and signing a
// colleague out is a denial of service indistinguishable from an idle timeout.
func TestOnePersonCannotSeeOrRevokeAnothersSessions(t *testing.T) {
	alice, _ := tokenUser(t, "e2e-sessions-alice",
		"e2e-sessions-alice-session-with-entropy-0123456789ab")
	bob, bobCSRF := tokenUser(t, "e2e-sessions-bob",
		"e2e-sessions-bob-session-with-entropy-0123456789abc")

	hers := listSessions(t, alice)
	if len(hers) == 0 {
		t.Fatal("no session to try against")
	}

	for _, s := range listSessions(t, bob) {
		if s.ID == hers[0].ID {
			t.Fatal("one person's listing contains another's session")
		}
	}

	if code := deleteSession(t, bob, bobCSRF, "/api/sessions/"+hers[0].ID); code != http.StatusNotFound {
		t.Fatalf("revoking somebody else's session returned %d, want 404", code)
	}

	// Not merely refused — still working. A 404 that revoked it anyway would
	// satisfy the assertion above and be exactly the bug this guards against.
	resp := request(t, alice, http.MethodGet, hostCardinal, "/api/auth/me", "application/json")
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the session was refused (%d) after somebody else was told 404 — "+
			"it was revoked despite the refusal", resp.StatusCode)
	}
}

// TestSigningOutEverywhereElseKeepsYouSignedIn.
//
// The whole reason this is not just "revoke all". Somebody who has lost a
// device is trying to secure their account, and ending their own session in the
// same click locks them out of the console mid-panic — which is how people end
// up not doing it at all.
func TestSigningOutEverywhereElseKeepsYouSignedIn(t *testing.T) {
	const login = "e2e-sessions-sweep"
	keep, keepCSRF := tokenUser(t, login,
		"e2e-sessions-sweep-keep-with-entropy-0123456789abc")

	// A second session for the same person, standing in for the lost laptop.
	other := extraSession(t, login, "e2e-sessions-sweep-other-with-entropy-0123456789")

	if got := len(listSessions(t, keep)); got < 2 {
		t.Fatalf("%d sessions, want at least 2 before sweeping", got)
	}

	if code := deleteSession(t, keep, keepCSRF, "/api/sessions"); code != http.StatusOK {
		t.Fatalf("revoking other sessions returned %d, want 200", code)
	}

	// The caller survives.
	resp := request(t, keep, http.MethodGet, hostCardinal, "/api/auth/me", "application/json")
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the caller was signed out by 'sign out everywhere else' (%d)",
			resp.StatusCode)
	}

	// The other does not.
	gone := request(t, other, http.MethodGet, hostCardinal, "/api/auth/me", "application/json")
	defer drain(gone)
	if gone.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the other session still works (%d) — nothing was revoked",
			gone.StatusCode)
	}

	if remaining := listSessions(t, keep); len(remaining) != 1 {
		t.Fatalf("%d sessions remain, want only the current one", len(remaining))
	}
}

// TestRevokingYourCurrentSessionSignsYouOut.
func TestRevokingYourCurrentSessionSignsYouOut(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-sessions-self",
		"e2e-sessions-self-with-entropy-0123456789abcdefgh")

	sessions := listSessions(t, c)
	var current string
	for _, s := range sessions {
		if s.Current {
			current = s.ID
		}
	}
	if current == "" {
		t.Fatal("no current session to revoke")
	}

	if code := deleteSession(t, c, csrf, "/api/sessions/"+current); code != http.StatusNoContent {
		t.Fatalf("revoking the current session returned %d, want 204", code)
	}

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/auth/me", "application/json")
	defer drain(resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d after ending the current session, want 401", resp.StatusCode)
	}
}

// TestTheListingSurfacesWhereASessionCameFrom.
//
// client_ip and user_agent have been columns since the first migration and
// nothing ever wrote them, so every session looked identical to every other and
// a list of them would have been a list of timestamps.
//
// This covers the read half only, and says so. Populating those columns needs a
// real login, and the only credential Cardinal accepts is a passkey — so the
// write half is asserted where a browser can tap one, in
// tools/uishot/verify-passkey.py. Seeding the values here and checking they come
// back would be a fine test of the query and a worthless one of the feature;
// splitting it is the honest arrangement, and the browser half is the half that
// would actually have caught the columns being empty.
func TestTheListingSurfacesWhereASessionCameFrom(t *testing.T) {
	const login = "e2e-sessions-origin"
	const token = "e2e-sessions-origin-with-entropy-0123456789abcdef"
	c, _ := tokenUser(t, login, token)

	seedSQL(t, `UPDATE sessions
	               SET client_ip = '203.0.113.7'::inet,
	                   user_agent = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/141.0'
	             WHERE token_hash = sha256('`+token+`'::bytea)`)

	for _, s := range listSessions(t, c) {
		if !s.Current {
			continue
		}
		if s.ClientIP != "203.0.113.7" {
			t.Errorf("clientIp is %q, want the recorded address", s.ClientIP)
		}
		if s.UserAgent == "" {
			t.Error("userAgent is empty — the console has nothing to show")
		}
		return
	}
	t.Fatal("the current session was not in its own listing")
}

// extraSession seeds a second live session for somebody, standing in for
// another browser on another machine.
func extraSession(t *testing.T, login, token string) *http.Client {
	t.Helper()

	seedSQL(t, `DELETE FROM sessions WHERE token_hash = sha256('`+token+`'::bytea)`)
	seedSQL(t, `INSERT INTO sessions
	              (subject_id, token_hash, valid_period, auth_method, auth_at,
	               device_bound, absolute_expiry, client_ip, user_agent)
	            SELECT e.id, sha256('`+token+`'::bytea),
	                   tstzrange(now(), now() + interval '1 hour'), 'passkey', now(),
	                   true, now() + interval '7 days',
	                   '198.51.100.4'::inet, 'Mozilla/5.0 (Macintosh) Safari/605'
	              FROM entities e WHERE e.name = '`+login+`'`)

	c := client(t)
	c.Jar.SetCookies(&url.URL{Scheme: "https", Host: hostCardinal + ":8443"},
		[]*http.Cookie{{Name: "cardinal_session", Value: token, Path: "/"}})
	return c
}
