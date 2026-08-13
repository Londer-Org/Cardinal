package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Setting a test up through the API rather than through the CLI.
//
// The commands these replace have moved off the database (ADR 0033), and
// granting requires a device-bound credential used minutes ago — so no
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

// adminLogin is that administrator's name, which the journal records for every
// change a fixture makes.
const adminLogin = "e2e-admin"

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

// projectionAfterwards restores an application's projection from a t.Cleanup,
// for the same reason revokeAfterwards exists: a cleanup runs after t.Context()
// has been cancelled.
func projectionAfterwards(app, mode string) {
	body := strings.NewReader(`{"mode":"` + mode + `"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut,
		origin(hostCardinal)+"/api/applications/"+app+"/projection", body)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+adminSessionToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := cleanupClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close() //nolint:errcheck // best effort cleanup
}

// sightAfterwards withdraws an allowance from a t.Cleanup.
func sightAfterwards(app, group string) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete,
		origin(hostCardinal)+"/api/applications/"+app+"/projection/groups/"+group, nil)
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

// createFixture makes an entity, tolerating one that is already there.
//
// Through the API for the same reason grantFixture is: creating an entity signs
// in now, and there is no browser in the container these ran in.
//
// What this replaced ran the CLI through a helper that discards the exit
// status, so a fixture which had stopped working looked exactly like one that
// had not, and the failure surfaced somewhere else entirely. This one fails
// where the mistake is.
func createFixture(t *testing.T, typeWord, name string, display ...string) {
	t.Helper()

	c, csrf := adminClient(t)

	// Users have an endpoint of their own, because they are the only type that
	// can be signed into and so the only one with an invitation to issue.
	path, body := "/api/directory/"+plural(typeWord), map[string]any{"name": name}
	if typeWord == "user" {
		path, body = "/api/directory/users", map[string]any{"login": name}
	}
	if len(display) > 0 {
		body["displayName"] = display[0]
	}

	resp, err := c.Do(jsonRequest(t, http.MethodPost, path, csrf, body))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	// 409 is a name already taken, which is the desired end state: re-running a
	// fixture is ordinary, and the suite reseeds.
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK, http.StatusConflict:
		return
	default:
		t.Fatalf("creating %s %s returned %d", typeWord, name, resp.StatusCode)
	}
}

// availabilityFixture disables or enables an entity, tolerating one that is
// already in the state asked for.
func availabilityFixture(t *testing.T, typeWord, name string, enable bool) {
	t.Helper()

	c, csrf := adminClient(t)

	method, path := http.MethodDelete, "/api/directory/"+plural(typeWord)+"/"+name
	if enable {
		method, path = http.MethodPost, path+"/enable"
	}

	resp, err := c.Do(jsonRequest(t, method, path, csrf, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	// 409 is "already in that state", which is the end state asked for. The
	// suite reseeds and several tests disable the same account.
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusConflict:
		return
	default:
		t.Fatalf("setting %s %s to enabled=%v returned %d",
			typeWord, name, enable, resp.StatusCode)
	}
}

// plural is the collection segment for a type word, mirroring Type.Plural.
//
// Spelled again here rather than imported, deliberately: this suite exercises
// the API from outside, and a test that builds its URLs from the server's own
// table would agree with the server about a path neither of them serves.
func plural(typeWord string) string {
	switch typeWord {
	case "service-account":
		return "service-accounts"
	default:
		return typeWord + "s"
	}
}

// registerAppFixture registers an application, returning its client id and
// secret. Both are empty for an application with no redirect URIs, which is a
// whole category rather than a failure.
//
// Unlike the others this does not tolerate an existing name: the secret is
// shown exactly once, so a caller that needs one needs the registration to have
// happened. Callers that only need the application to exist check first.
func registerAppFixture(t *testing.T, body map[string]any) (clientID, secret string) {
	t.Helper()

	c, csrf := adminClient(t)
	resp, err := c.Do(jsonRequest(t, http.MethodPost, "/api/applications", csrf, body))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("registering %v returned %d", body["name"], resp.StatusCode)
	}

	var out struct {
		ClientID string `json:"clientId"`
		Secret   string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("reading the registration: %v", err)
	}
	return out.ClientID, out.Secret
}

// appExistsFixture reports whether an application is registered, so a caller
// can skip a registration whose one-time secret it does not need.
func appExistsFixture(t *testing.T, name string) bool {
	t.Helper()

	c, _ := adminClient(t)
	resp := request(t, c, http.MethodGet, hostCardinal, "/api/applications", "application/json")
	defer drain(resp)

	var apps []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apps); err != nil {
		t.Fatalf("listing applications: %v", err)
	}
	for _, a := range apps {
		if a.Name == name {
			return true
		}
	}
	return false
}

// projectionModeFixture sets which groups an application is told about.
func projectionModeFixture(t *testing.T, app, mode string) {
	t.Helper()

	c, csrf := adminClient(t)
	resp, err := c.Do(jsonRequest(t, http.MethodPut,
		"/api/applications/"+app+"/projection", csrf, map[string]string{"mode": mode}))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("setting %s to %s mode returned %d", app, mode, resp.StatusCode)
	}
}

// sightFixture grants or withdraws an application's sight of a group it does
// not own, returning the status so a test asserting a refusal can read it.
func sightFixture(t *testing.T, app, group string, allow bool) (int, string) {
	t.Helper()

	c, csrf := adminClient(t)
	method := http.MethodPost
	if !allow {
		method = http.MethodDelete
	}

	resp, err := c.Do(jsonRequest(t, method,
		"/api/applications/"+app+"/projection/groups/"+group, csrf, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	body, _ := io.ReadAll(resp.Body) //nolint:errcheck // the status is the assertion; the body is context for it
	return resp.StatusCode, string(body)
}

// posixFixture gives a user or group a number, tolerating one that has it.
//
// Idempotent on both sides: a number cannot change once allocated, so the
// endpoints answer with the existing one rather than refusing.
func posixFixture(t *testing.T, kind, name string) {
	t.Helper()

	c, csrf := adminClient(t)

	path := "/api/directory/users/" + name + "/posix"
	if kind == "group" {
		path = "/api/directory/groups/" + name + "/posix"
	}

	resp, err := c.Do(jsonRequest(t, http.MethodPut, path, csrf, map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("assigning a number to %s %s returned %d", kind, name, resp.StatusCode)
	}
}
