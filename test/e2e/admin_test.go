package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The admin API, gated by Cedar.
//
// Cardinal's own administration runs through the same policy engine as web
// access, SSH and sudo (ADR 0005) — there is no separate admin ACL of the kind
// LDAP has. Most of these exercise refusals, because that is the half worth
// being sure about: an ordinary signed-in user must not be able to register an
// OIDC client, and the suite keeps a separate account for the admin case so the
// refusals cannot pass vacuously.

// TestOrdinaryUserCannotReachTheAdminAPI.
//
// Being signed in is not being an administrator. Anyone who can register an
// OIDC client chooses its redirect URIs, which is enough to stand up a
// convincing phishing surface inside the organisation's own identity provider —
// so this is the boundary that matters most on the whole admin API.
func TestOrdinaryUserCannotReachTheAdminAPI(t *testing.T) {
	// Ensures the admin account exists and the ordinary one is demoted,
	// whatever previous runs left behind.
	adminClient(t)

	c := signedInClient(t)
	csrf := csrfToken(t, c)

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/applications"},
		{http.MethodPost, "/api/applications"},
		{http.MethodGet, "/api/applications/anything"},
		{http.MethodDelete, "/api/applications/anything"},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.method+" "+endpoint.path, func(t *testing.T) {
			// CSRF runs ahead of the policy gate — correctly, since it is the
			// cheaper check and a different class of rejection. Sending a valid
			// token is what makes this a test of authorization rather than of
			// CSRF, which is covered elsewhere.
			resp := requestWithCSRF(t, c, endpoint.method, endpoint.path, csrf)
			defer drain(resp)

			body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows

			// 403 specifically. A 401 would say "sign in", which this session
			// already has done, and a 404 would hide that the endpoint exists.
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s returned %d, want 403: %s",
					endpoint.method, endpoint.path, resp.StatusCode, body)
			}

			// The deciding policy is named. "Access denied" with no reason is
			// the thing this project exists to stop doing.
			var denial struct {
				Error  string   `json:"error"`
				Policy []string `json:"policy"`
			}
			if err := json.Unmarshal(body, &denial); err != nil {
				t.Fatalf("denial was not JSON: %s", body)
			}
			// Nothing matched, so nothing is named: this is default-deny, and
			// the message has to say so rather than implying a rule fired.
			if len(denial.Policy) != 0 {
				t.Errorf("denial named %v, but no policy should match an ordinary "+
					"user asking to administer", denial.Policy)
			}
			if !strings.Contains(denial.Error, "directory-admins") {
				t.Errorf("denial message %q does not say what is missing, so the "+
					"reader cannot tell why they were refused", denial.Error)
			}
		})
	}
}

// TestAdminDenialIsLoggedAsADecision.
//
// A refusal nobody can look up afterwards is indistinguishable from a bug. The
// decision explorer must be able to answer "why was I denied?" for the admin
// API exactly as it does for web access.
func TestAdminDenialIsLoggedAsADecision(t *testing.T) {
	adminClient(t) // demotes the ordinary account

	c := signedInClient(t)

	//nolint:bodyclose // drain closes it
	resp := request(t, c, http.MethodGet, hostCardinal, "/api/applications", "application/json")
	drain(resp)

	decisions := request(t, c, http.MethodGet, hostCardinal,
		"/api/decisions?limit=100&denied=true", "application/json")
	defer drain(decisions)

	var records []struct {
		DecisionPoint string   `json:"decisionPoint"`
		Action        string   `json:"action"`
		Allowed       bool     `json:"allowed"`
		Reasons       []string `json:"reasons"`
		Explanation   string   `json:"explanation"`
	}
	if err := json.NewDecoder(decisions.Body).Decode(&records); err != nil {
		t.Fatal(err)
	}

	// The action the endpoint actually asks for. This used to assert
	// AdministerDirectory, which stopped being what /api/applications evaluates
	// the moment administration was split into tiers — and kept passing on
	// records another test had written.
	for _, record := range records {
		if record.DecisionPoint == "adminAPI" &&
			record.Action == "ManageApplications" && !record.Allowed {
			if record.Explanation == "" {
				t.Error("the decision carries no explanation, so the explorer has nothing to show")
			}
			return
		}
	}
	t.Fatalf("the refused admin request was not logged as a decision; saw %d records",
		len(records))
}

// TestUnauthenticatedAdminAPIIsUnauthorized.
//
// 401 rather than 403: there is nobody to evaluate a policy for yet, and
// telling an anonymous caller "you are not permitted" implies a decision that
// was never made.
func TestUnauthenticatedAdminAPIIsUnauthorized(t *testing.T) {
	c := client(t)

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/applications", "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request returned %d, want 401", resp.StatusCode)
	}
}

// adminClient returns a client holding a session that can actually administer.
//
// A different account from the one establishSession uses, deliberately.
// Promoting the shared account would make every "this is refused" test pass
// vacuously the moment an admin test had run — the suite would still be green
// and would be checking nothing.
//
// The session is inserted straight into the database rather than obtained by
// signing in, because the only credential Cardinal accepts is a passkey and
// tapping one needs a human. What is inserted is exactly what a passkey sign-in
// produces, so everything downstream of authentication is genuinely exercised.
func adminClient(t *testing.T) (*http.Client, string) {
	t.Helper()

	const token = adminSessionToken
	const login = "e2e-admin"

	seedSQL(t, `INSERT INTO entities (type, name, display_name)
	            VALUES ('user', '`+login+`', 'End-to-end Administrator')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)

	seedSQL(t, `INSERT INTO group_members (group_id, member_id, granted_by, valid_period)
	            SELECT '`+adminGroupID+`', e.id, e.id, tstzrange(now(), 'infinity')
	              FROM entities e WHERE e.name = '`+login+`'
	            ON CONFLICT DO NOTHING`)

	// The ordinary account must never be an administrator, or the refusal
	// tests stop testing anything. Previous runs granted it, so this undoes
	// that rather than assuming a clean database.
	seedSQL(t, `DELETE FROM group_members
	             WHERE group_id = '`+adminGroupID+`'
	               AND member_id = (SELECT id FROM entities WHERE name = 'e2e-user')`)

	seedSQL(t, `DELETE FROM sessions WHERE token_hash = sha256('`+token+`'::bytea)`)
	seedSQL(t, `INSERT INTO sessions
	              (subject_id, token_hash, valid_period, auth_method, auth_at,
	               device_bound, absolute_expiry)
	            SELECT e.id, sha256('`+token+`'::bytea),
	                   tstzrange(now(), now() + interval '1 hour'), 'passkey', now(),
	                   true, now() + interval '7 days'
	              FROM entities e WHERE e.name = '`+login+`'`)

	c := client(t)
	c.Jar.SetCookies(&url.URL{Scheme: "http", Host: hostCardinal},
		[]*http.Cookie{{Name: "cardinal_session", Value: token, Path: "/"}})

	return c, csrfToken(t, c)
}

// adminGroupID mirrors policy.AdminGroupID and migration 0008. A unit test
// asserts the shipped policy agrees; this is the third copy, and if it drifts
// these tests fail loudly rather than quietly testing nothing.
const adminGroupID = "00000000-0000-7000-8000-00000000ad11"

// postExpectingFailure posts a body and returns the response whatever it is.
//
// postJSON fails the test on a non-2xx, which is right almost everywhere and
// wrong for the refusals worth asserting — a hostname another application
// already holds is one of them.
func postExpectingFailure(
	t *testing.T, c *http.Client, csrf, path string, body any,
) *http.Response {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+path, strings.NewReader(string(encoded)))
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
	return resp
}

// applicationEntry is one row of /api/applications.
//
// An application entity, which may or may not also be an OIDC relying party.
// oidc is null for something that only sits behind the proxy — the case the
// console could not see at all until it was keyed on the entity.
type applicationEntry struct {
	Name      string   `json:"name"`
	Disabled  bool     `json:"disabled"`
	Hostnames []string `json:"hostnames"`
	OIDC      *struct {
		ClientID string `json:"clientId"`
	} `json:"oidc"`
}

func listApplications(t *testing.T, c *http.Client) []applicationEntry {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/applications", "application/json")
	defer drain(resp)

	var out []applicationEntry
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func findApplication(t *testing.T, c *http.Client, name string) applicationEntry {
	t.Helper()

	for _, a := range listApplications(t, c) {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("%s is not in the application list", name)
	return applicationEntry{}
}

// TestAdminCanManageAProxiedApplication.
//
// The gap this closes. An application behind forwardAuth speaks no OIDC, so it
// has no redirect URIs and no client id — and the console listed OIDC clients,
// which meant the commonest kind of protected thing could not be created,
// found, given a hostname, or retired from the admin API at all. `cardinal app
// hostname` was the only route.
func TestAdminCanManageAProxiedApplication(t *testing.T) {
	c, csrf := adminClient(t)
	name := "e2e-proxied-app"
	hostname := "e2e-proxied.cardinal.test"

	// Idempotent across runs, the way the test above is: an application is
	// never deleted, so a previous run's is renamed out of the way and its
	// hostname released. Without the second statement the run after the first
	// would collide on the address rather than on the name, which is a more
	// confusing way to fail.
	seedSQL(t, `DELETE FROM application_hostnames WHERE hostname = '`+hostname+`'`)
	seedSQL(t, `UPDATE entities SET name = name || '-' || id WHERE name = '`+name+`'`)

	// Registered with no redirect URIs, which is what says "this one is behind
	// the proxy" rather than being an incomplete form.
	var created applicationEntry
	//nolint:bodyclose // postJSON closes the body before returning
	postJSON(t, c, "/api/applications", csrf, map[string]any{
		"name":        name,
		"displayName": "Proxied by the admin API",
	}, &created)

	if created.Name != name {
		t.Fatalf("registered %q, got %q", name, created.Name)
	}

	listed := findApplication(t, c, name)
	if listed.OIDC != nil {
		t.Error("an application registered with no redirect URIs came back with " +
			"an OIDC client; the two kinds must stay distinguishable")
	}
	if len(listed.Hostnames) != 0 {
		t.Errorf("a new application already answers to %v", listed.Hostnames)
	}

	// A hostname, which is what makes forwardAuth able to find it at all.
	//nolint:bodyclose // postJSON closes the body before returning
	postJSON(t, c, "/api/applications/"+name+"/hostnames", csrf,
		map[string]any{"hostname": hostname}, nil)

	withHostname := findApplication(t, c, name)
	if len(withHostname.Hostnames) != 1 || withHostname.Hostnames[0] != hostname {
		t.Fatalf("hostnames are %v, want [%s]", withHostname.Hostnames, hostname)
	}

	// Two applications cannot hold one address: whichever won would decide
	// which application's group memberships govern requests arriving there.
	//nolint:bodyclose // postExpectingFailure drains it before returning
	conflict := postExpectingFailure(t, c, csrf,
		"/api/applications/protected-app/hostnames",
		map[string]any{"hostname": hostname})
	if conflict.StatusCode != http.StatusConflict {
		t.Errorf("claiming a taken hostname returned %d, want 409", conflict.StatusCode)
	}

	// Retiring reaches it, which disabling-by-client-id could not.
	retire := requestWithCSRF(t, c, http.MethodPost,
		"/api/applications/"+name+"/disable", csrf)
	drain(retire)
	if retire.StatusCode != http.StatusNoContent {
		t.Fatalf("retiring returned %d, want 204", retire.StatusCode)
	}
	if !findApplication(t, c, name).Disabled {
		t.Error("it was retired and the list still says otherwise")
	}

	// An unrecognised action must not mean disable. Deriving the boolean from
	// `== "enable"` would make every typo in this URL retire an application
	// and report success.
	nonsense := requestWithCSRF(t, c, http.MethodPost,
		"/api/applications/"+name+"/frobnicate", csrf)
	drain(nonsense)
	if nonsense.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown action returned %d, want 404", nonsense.StatusCode)
	}

	// And back.
	restore := requestWithCSRF(t, c, http.MethodPost,
		"/api/applications/"+name+"/enable", csrf)
	drain(restore)
	if restore.StatusCode != http.StatusNoContent {
		t.Fatalf("restoring returned %d, want 204", restore.StatusCode)
	}
	if findApplication(t, c, name).Disabled {
		t.Error("it was restored and the list still says retired")
	}
}

// TestAdminCanManageApplications is the allowed path, end to end.
func TestAdminCanManageApplications(t *testing.T) {
	c, csrf := adminClient(t)

	// The UI decides what to render from this, so it has to agree with what
	// the endpoints actually permit.
	var me struct {
		CanAdminister bool `json:"canAdminister"`
	}
	meResp := request(t, c, http.MethodGet, hostCardinal, "/api/auth/me", "application/json")
	if err := json.NewDecoder(meResp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	drain(meResp)
	if !me.CanAdminister {
		t.Fatal("a directory-admins member with fresh device-bound auth was told they cannot administer")
	}

	// Names are unique per type across disabled entities too — disabling is a
	// soft delete, so a previous run's application still holds the name. Renamed
	// with its own id rather than a fixed suffix, so this stays idempotent
	// however many times the suite runs.
	name := "e2e-managed-app"
	seedSQL(t, `UPDATE entities SET name = name || '-' || id WHERE name = '`+name+`'`)

	var registered struct {
		ClientID string `json:"clientId"`
		Secret   string `json:"secret"`
		Public   bool   `json:"public"`
	}
	//nolint:bodyclose // postJSON closes the body before returning
	postJSON(t, c, "/api/applications", csrf, map[string]any{
		"name":         name,
		"displayName":  "Managed by the admin API",
		"redirectUris": []string{"https://managed.example.com/callback"},
		"scopes":       []string{"openid", "profile"},
		"confidential": true,
	}, &registered)

	if registered.Secret == "" {
		t.Error("a confidential client was registered without a secret")
	}
	if registered.Public {
		t.Error("a client registered with confidential:true came back public")
	}

	// It appears in the list.
	//
	// The list is applications, not OIDC clients, so the client id is nested
	// under oidc and is null for something that only sits behind the proxy.
	// That distinction is the point: the flat version made an entire category
	// invisible in the console.
	applications := listApplications(t, c)

	found := false
	for _, a := range applications {
		if a.OIDC != nil && a.OIDC.ClientID == registered.ClientID {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s was registered but is not in the list", name)
	}

	// And it can be inspected.
	detailResp := request(t, c, http.MethodGet, hostCardinal,
		"/api/applications/"+registered.ClientID, "application/json")
	defer drain(detailResp)
	if detailResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(detailResp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("inspecting returned %d: %s", detailResp.StatusCode, body)
	}
	var detail struct {
		ActiveTokens int    `json:"activeTokens"`
		Secret       string `json:"secret"`
	}
	if err := json.NewDecoder(detailResp.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.Secret != "" {
		t.Error("the client secret was returned when inspecting an application — " +
			"it is shown once at registration and only its hash is stored")
	}

	// Disabling retires it.
	disableResp := requestWithCSRF(t, c, http.MethodDelete,
		"/api/applications/"+registered.ClientID, csrf)
	drain(disableResp)
	if disableResp.StatusCode != http.StatusNoContent {
		t.Fatalf("disabling returned %d, want 204", disableResp.StatusCode)
	}

	gone := request(t, c, http.MethodGet, hostCardinal,
		"/api/applications/"+registered.ClientID, "application/json")
	drain(gone)
	if gone.StatusCode != http.StatusNotFound {
		t.Errorf("a disabled application is still readable (%d)", gone.StatusCode)
	}
}

// TestAdminCannotRegisterAWildcardRedirect.
//
// The validation the CLI performs must hold over the API too. A rule enforced
// on one path is a rule with a way around it, and this is the one that matters
// most: anyone who can register a wildcard redirect can receive authorization
// codes for every user of that application.
func TestAdminCannotRegisterAWildcardRedirect(t *testing.T) {
	c, csrf := adminClient(t)

	body, err := json.Marshal(map[string]any{
		"name":         "wildcard-attempt",
		"redirectUris": []string{"https://*.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+"/api/applications", strings.NewReader(string(body)))
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

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a wildcard redirect URI was accepted over the API (%d)", resp.StatusCode)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// requestWithCSRF issues a request carrying the double-submit token.
func requestWithCSRF(t *testing.T, c *http.Client, method, path, csrf string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, origin(hostCardinal)+path, nil) //nolint:noctx // bounded by client timeout
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Cardinal-CSRF", csrf)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// drain closes a response body.
//
// Wrapped because the error is genuinely uninteresting in a test — there is
// nothing to do about a failed close on a response already read — and nine
// copies of the same discard read worse than one named function.
func drain(resp *http.Response) { _ = resp.Body.Close() } //nolint:errcheck // nothing actionable remains once the body is read
