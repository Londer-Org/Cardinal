package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

// The admin API, gated by Cedar.
//
// Cardinal's own administration runs through the same policy engine as web
// access, SSH and sudo (ADR 0005) — there is no separate admin ACL of the kind
// LDAP has. These tests exercise the refusals, because the e2e suite signs in
// with break-glass, and break-glass is explicitly forbidden from administering.
// That makes it exactly the credential this gate must hold against.

// TestBreakGlassCannotReachTheAdminAPI.
//
// The whole point of ADR 0009's emergency key is restoring access, not working
// with it. If a break-glass session could register OIDC clients, a stolen
// offline key would go from serious to catastrophic: register a client with a
// redirect URI you control and you have an identity provider phishing its own
// users, with the organisation's real domain in the address bar.
func TestBreakGlassCannotReachTheAdminAPI(t *testing.T) {
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

			body, _ := io.ReadAll(resp.Body)

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
			if !contains(denial.Policy, "break-glass-cannot-administer") {
				t.Errorf("denial named %v, expected the break-glass rule — a refusal "+
					"that cannot say which policy fired is not explicable", denial.Policy)
			}
			if !strings.Contains(denial.Error, "emergency") {
				t.Errorf("denial message %q does not mention emergency access, so "+
					"the reader cannot tell why they were refused", denial.Error)
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

	for _, record := range records {
		if record.DecisionPoint == "adminAPI" && record.Action == "AdministerDirectory" {
			if record.Allowed {
				t.Fatal("a break-glass session was allowed to administer the directory")
			}
			if record.Explanation == "" {
				t.Error("the decision carries no explanation, so the explorer has nothing to show")
			}
			return
		}
	}
	t.Fatal("the refused admin request was not logged as a decision")
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
// The session is inserted straight into the database rather than obtained by
// signing in, because the only credential that satisfies the policy is a
// device-bound passkey, and tapping one needs a human with a security key. What
// is inserted is exactly what a passkey sign-in would produce — auth_method
// passkey, device_bound true, authenticated now — so everything downstream of
// authentication is genuinely exercised. Only the WebAuthn ceremony is skipped,
// and that is covered by its own tests plus a human in a browser.
//
// The subject is also granted directory-admins, the ordinary way, because the
// permit rule is what is under test.
func adminClient(t *testing.T) (*http.Client, string) {
	t.Helper()

	//nolint:gosec // a session token for a throwaway container, not a credential
	const token = "e2e-admin-session-token-with-plenty-of-entropy-0123456789"

	psql(t, `INSERT INTO group_members (group_id, member_id, granted_by, valid_period)
	         SELECT '`+adminGroupID+`', e.id, e.id, tstzrange(now(), 'infinity')
	           FROM entities e WHERE e.name = 'e2e-user'
	         ON CONFLICT DO NOTHING`)

	psql(t, `DELETE FROM sessions WHERE token_hash = sha256('`+token+`'::bytea)`)
	psql(t, `INSERT INTO sessions
	           (subject_id, token_hash, valid_period, auth_method, auth_at, device_bound)
	         SELECT e.id, sha256('`+token+`'::bytea),
	                tstzrange(now(), now() + interval '1 hour'), 'passkey', now(), true
	           FROM entities e WHERE e.name = 'e2e-user'`)

	c := client(t)
	c.Jar.SetCookies(&url.URL{Scheme: "http", Host: hostCardinal},
		[]*http.Cookie{{Name: "cardinal_session", Value: token, Path: "/"}})

	return c, csrfToken(t, c)
}

// adminGroupID mirrors policy.AdminGroupID and migration 0008. A unit test
// asserts the shipped policy agrees; this is the third copy, and if it drifts
// these tests fail loudly rather than quietly testing nothing.
const adminGroupID = "00000000-0000-7000-8000-00000000ad11"

func psql(t *testing.T, statement string) {
	t.Helper()

	//nolint:gosec // the statement is written in this file, not taken from input
	out, err := exec.CommandContext(t.Context(), "docker", "compose",
		"-f", "../../examples/compose.yml",
		"exec", "-T", "postgres", "psql", "-U", "cardinal", "-d", "cardinal",
		"-v", "ON_ERROR_STOP=1", "-c", statement).CombinedOutput()
	if err != nil {
		t.Fatalf("psql: %v\n%s", err, out)
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
	psql(t, `UPDATE entities SET name = name || '-' || id WHERE name = '`+name+`'`)

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
	listResp := request(t, c, http.MethodGet, hostCardinal, "/api/applications", "application/json")
	var applications []struct {
		ClientID string `json:"clientId"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&applications); err != nil {
		t.Fatal(err)
	}
	drain(listResp)

	found := false
	for _, a := range applications {
		if a.ClientID == registered.ClientID {
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
		body, _ := io.ReadAll(detailResp.Body)
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
		"http://"+hostCardinal+"/api/applications", strings.NewReader(string(body)))
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

	req, err := http.NewRequest(method, "http://"+hostCardinal+path, nil) //nolint:noctx // bounded by client timeout
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
func drain(resp *http.Response) { _ = resp.Body.Close() }
