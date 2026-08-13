package e2e

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// Setting a test up through the API rather than through the CLI.
//
// The commands these replace are moving off the database (ADR 0033), and
// granting will then require a device-bound credential used minutes ago — so no
// unattended process can ever do it. That is the intended answer to "our
// pipeline needs to grant memberships", and it applies to this suite: there is
// no browser in the container these ran in.
//
// So the fixtures do what an administrator does, with the database credential
// used for the one thing it is for here — minting a session to act through.
// The grant still goes through policy, and the journal still names the account
// it was made by, which a direct INSERT would have skipped.

// adminSessionToken is the administrator these fixtures act as. Shared with
// adminClient, which seeds the row it refers to.
const adminSessionToken = "e2e-admin-session-token-with-plenty-of-entropy-0123456789"

// grantFixture puts a member in a group, tolerating one that is already there.
//
// Re-running a fixture is ordinary — the suite reseeds, and several tests grant
// the same membership — so an existing grant is the desired end state rather
// than an error. The exclusion constraint answers 409 for it, which is the
// temporal model doing its job.
func grantFixture(t *testing.T, group, member string, reason ...string) {
	t.Helper()

	c, csrf := adminClient(t)

	body := map[string]any{"member": member}
	if len(reason) > 0 {
		body["reason"] = reason[0]
	}

	resp, err := c.Do(jsonRequest(t, http.MethodPost,
		"/api/directory/groups/"+group+"/members", csrf, body))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusCreated, http.StatusConflict:
		return
	default:
		t.Fatalf("granting %s membership of %s returned %d", member, group, resp.StatusCode)
	}
}

// revokeFixture ends a membership, tolerating one that is already gone.
func revokeFixture(t *testing.T, group, member string) {
	t.Helper()

	c, csrf := adminClient(t)

	resp, err := c.Do(jsonRequest(t, http.MethodDelete,
		"/api/directory/groups/"+group+"/members/"+member, csrf, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		return
	default:
		t.Fatalf("revoking %s from %s returned %d", member, group, resp.StatusCode)
	}
}

// cleanupClient dials the stack the way client(t) does, without needing a
// testing.T that is already finished.
var cleanupClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, gateway())
		},
	},
	Timeout: 15 * time.Second,
}

// revokeAfterwards ends a membership from a t.Cleanup.
//
// Separate from revokeFixture because a cleanup runs after t.Context() has been
// cancelled, so anything built on it dies with "context canceled" — which is
// what cliBackground existed to avoid when these went through the CLI.
//
// Authenticates with the administrator's session as a bearer token rather than
// a cookie, which is what the CLI does and what keeps this off the CSRF path: a
// caller holding a header credential has no ambient authority to abuse.
func revokeAfterwards(group, member string) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete,
		origin(hostCardinal)+"/api/directory/groups/"+group+"/members/"+member, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+adminSessionToken)

	resp, err := cleanupClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close() //nolint:errcheck // best effort cleanup
}
