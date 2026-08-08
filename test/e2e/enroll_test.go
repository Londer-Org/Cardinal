package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Enrollment, through the real stack.
//
// These endpoints are the only unauthenticated write path besides sign-in, so
// what they refuse matters more than what they permit. The permitting half ends
// in a WebAuthn ceremony, which needs a human with a key — so the store tests
// cover redemption and these cover the boundary.

// TestEnrollmentRequiresAnInvitation.
func TestEnrollmentRequiresAnInvitation(t *testing.T) {
	c := client(t)
	csrf := csrfToken(t, c)

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{name: "no token", token: "", want: http.StatusBadRequest},
		{name: "made-up token", token: "clearly-not-a-real-invitation", want: http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := request(t, c, http.MethodGet, hostCardinal,
				"/api/enroll?token="+url.QueryEscape(tc.token), "application/json")
			defer drain(resp)

			if resp.StatusCode != tc.want {
				body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
				t.Fatalf("got %d, want %d: %s", resp.StatusCode, tc.want, body)
			}
		})
	}

	t.Run("begin refuses a made-up token", func(t *testing.T) {
		body := strings.NewReader(`{"token":"clearly-not-a-real-invitation"}`)
		req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
			origin(hostCardinal)+"/api/enroll/begin", body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Cardinal-CSRF", csrf)

		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer drain(resp)

		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("beginning enrollment with a bogus token returned %d, want 404",
				resp.StatusCode)
		}
	})
}

// TestInvitationDoesNotLeakWhetherAnAccountExists.
//
// The refusal for a made-up token must not differ from the refusal for a real
// account's expired link. Otherwise the endpoint answers "does alice exist?"
// to anyone willing to try.
func TestInvitationDoesNotLeakWhetherAnAccountExists(t *testing.T) {
	c := client(t)

	bodies := make([]string, 0, 2)
	for _, token := range []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	} {
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/enroll?token="+token, "application/json")
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		drain(resp)
		bodies = append(bodies, string(body))
	}

	if bodies[0] != bodies[1] {
		t.Errorf("two invalid tokens produced different answers:\n  %s\n  %s",
			bodies[0], bodies[1])
	}
}

// TestIssuingAnInvitationIsAdministration.
//
// Anyone who can issue an invitation can take over the named account, so it
// sits behind the same Cedar gate as everything else. An ordinary signed-in
// user must be refused: otherwise any employee could mint a credential on a
// colleague's account.
func TestIssuingAnInvitationIsAdministration(t *testing.T) {
	adminClient(t) // ensures the ordinary account is not an administrator

	c := signedInClient(t)
	csrf := csrfToken(t, c)

	body := strings.NewReader(`{"login":"e2e-user"}`)
	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+"/api/invitations", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cardinal-CSRF", csrf)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusForbidden {
		payload, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("an ordinary user issued an invitation (%d): %s — any employee "+
			"could then mint a credential on a colleague's account",
			resp.StatusCode, payload)
	}
}

// TestAdminCanIssueAndRevokeAnInvitation walks the administrative half.
func TestAdminCanIssueAndRevokeAnInvitation(t *testing.T) {
	c, csrf := adminClient(t)

	// A throwaway account, created directly so the test does not depend on the
	// user-creation API existing yet.
	const login = "e2e-invitee"
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', '`+login+`')
	         ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)

	var issued struct {
		Login    string `json:"login"`
		URL      string `json:"url"`
		Recovery bool   `json:"recovery"`
	}
	//nolint:bodyclose // postJSON closes the body before returning
	postJSON(t, c, "/api/invitations", csrf, map[string]any{"login": login}, &issued)

	if !strings.Contains(issued.URL, "/enroll?token=") {
		t.Fatalf("issued URL %q is not an enrollment link", issued.URL)
	}
	if issued.Recovery {
		t.Error("a fresh account was reported as a recovery")
	}

	// The link resolves, unauthenticated, and names the account.
	token := issued.URL[strings.Index(issued.URL, "token=")+len("token="):]
	anon := client(t)
	resp := request(t, anon, http.MethodGet, hostCardinal,
		"/api/enroll?token="+url.QueryEscape(token), "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("the issued invitation does not resolve (%d): %s", resp.StatusCode, body)
	}
	var details struct {
		Login           string `json:"login"`
		AlreadyEnrolled bool   `json:"alreadyEnrolled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		t.Fatal(err)
	}
	if details.Login != login {
		t.Errorf("invitation names %q, want %q — someone following a link out of "+
			"a chat message must see whose account it is", details.Login, login)
	}
	if details.AlreadyEnrolled {
		t.Error("a fresh account reported existing credentials")
	}

	// Revoking kills it.
	revoked := requestWithCSRF(t, c, http.MethodDelete, "/api/invitations/"+login, csrf)
	drain(revoked)
	if revoked.StatusCode != http.StatusNoContent {
		t.Fatalf("revoking returned %d, want 204", revoked.StatusCode)
	}

	gone := request(t, anon, http.MethodGet, hostCardinal,
		"/api/enroll?token="+url.QueryEscape(token), "application/json")
	defer drain(gone)
	if gone.StatusCode != http.StatusNotFound {
		t.Errorf("a revoked invitation still resolves (%d)", gone.StatusCode)
	}
}
