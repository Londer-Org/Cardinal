package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Access tokens: what a script gets instead of a passkey.
//
// The arrangement these replace is a routing rule that matches the
// Authorization header and sends API traffic *around* the auth proxy, because
// the proxy has no idea what the application's tokens are. That works, and it
// costs the thing this project exists to provide: the request never reaches a
// policy decision, so the one class of traffic that runs unattended is the one
// class absent from the decision log.
//
// The whole design rests on a token being a weaker credential rather than a
// second kind of principal — so these tests are mostly about what it *cannot*
// do.

// tokenOwnerLogin is the seeded administrator. Deliberately the *most*
// privileged account in the stack: a token that cannot administer while owned
// by someone who can is the only version of this test that proves anything.
const tokenOwnerLogin = "e2e-admin"

// tokenFor issues an access token through the CLI, which is how an operator
// would.
func tokenFor(t *testing.T) string {
	t.Helper()

	// Seeds the account and its directory-admin membership, which is what makes
	// the refusals below meaningful.
	adminClient(t)

	out := cardinalCLI(t, "token", "create", tokenOwnerLogin, "-name", "e2e", "-for", "1h")
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "crd_pat_") {
			return field
		}
	}
	t.Fatalf("no token in output: %s", out)
	return ""
}

func bearerRequest(t *testing.T, method, path, token string, headers map[string]string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, "http://"+hostCardinal+path, nil) //nolint:noctx // bounded by client timeout
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client(t).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, hostCardinal+path, err)
	}
	return resp
}

// TestAccessTokenAuthenticatesItsOwner.
//
// The token is the owner, with one difference that the rest of these tests
// depend on: it is never device-bound.
func TestAccessTokenAuthenticatesItsOwner(t *testing.T) {
	token := tokenFor(t)

	resp := bearerRequest(t, http.MethodGet, "/api/auth/me", token, nil)
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200 — a valid token did not authenticate", resp.StatusCode)
	}

	var me struct {
		Login       string `json:"login"`
		AuthMethod  string `json:"authMethod"`
		DeviceBound bool   `json:"deviceBound"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}

	if me.Login != tokenOwnerLogin {
		t.Errorf("token authenticated as %q, want %q", me.Login, tokenOwnerLogin)
	}
	if me.AuthMethod != "access_token" {
		t.Errorf("authMethod is %q — the decision log needs this to answer "+
			"'what did automation do'", me.AuthMethod)
	}
	if me.DeviceBound {
		t.Error("a token reported itself device-bound, which would hand a string " +
			"in a CI variable the authority of a hardware key")
	}
}

// TestAccessTokenCannotAdminister.
//
// The security property, and the reason this feature needed no new policy: the
// existing `admin-requires-fresh-device-bound-auth` forbid is written
// `unless { principal.deviceBound && … }`, so a token fails it by construction.
//
// The owner here is a full directory administrator. If the token could
// administer, it would be because the credential conferred it — which is
// precisely what must not happen.
func TestAccessTokenCannotAdminister(t *testing.T) {
	token := tokenFor(t)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/directory/users"},
		{http.MethodGet, "/api/directory/groups"},
		{http.MethodGet, "/api/applications"},
		{http.MethodGet, "/api/recoveries"},
		{http.MethodPost, "/api/directory/users"},
		{http.MethodPost, "/api/invitations"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp := bearerRequest(t, tc.method, tc.path, token, nil)
			defer drain(resp)

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("got %d, want 403 — an access token reached an "+
					"administrative endpoint", resp.StatusCode)
			}
		})
	}
}

// TestAccessTokenRefusalNamesThePolicy.
//
// Not decoration. A refusal that cannot say which rule produced it is one
// nobody can act on, and the freshness rule is the one an operator most needs
// to recognise here — because the fix is "this is not something a token may do"
// rather than "your token is broken".
func TestAccessTokenRefusalNamesThePolicy(t *testing.T) {
	token := tokenFor(t)

	resp := bearerRequest(t, http.MethodGet, "/api/directory/users", token, nil)
	defer drain(resp)

	var body struct {
		Error  string   `json:"error"`
		Policy []string `json:"policy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	if len(body.Policy) == 0 {
		t.Fatal("refusal named no policy")
	}
	if !strings.Contains(strings.Join(body.Policy, ","),
		"admin-requires-fresh-device-bound-auth") {
		t.Errorf("refused by %v, expected the device-bound freshness rule — if "+
			"something else is refusing, the property this design relies on is "+
			"not the one being enforced", body.Policy)
	}
}

// TestAccessTokenReachesAProtectedApplication.
//
// The point of the whole thing. A script presents a token to the same
// forwardAuth endpoint a browser uses, and the application behind it receives
// the same identity headers — so it needs no idea that tokens exist, and the
// proxy needs no rule routing API traffic around the check.
func TestAccessTokenReachesAProtectedApplication(t *testing.T) {
	token := tokenFor(t)

	resp := bearerRequest(t, http.MethodGet, "/api/auth/verify", token,
		map[string]string{
			"X-Forwarded-Host":   hostProtected,
			"X-Forwarded-Uri":    "/",
			"X-Forwarded-Method": http.MethodGet,
		})
	defer drain(resp)

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d — a token was refused access a session would have been "+
			"granted, which leaves the proxy bypass as the only option",
			resp.StatusCode)
	}
	if got := resp.Header.Get("X-Auth-Request-Preferred-Username"); got != tokenOwnerLogin {
		t.Errorf("identity header says %q, want %q — the application behind the "+
			"proxy reads this and nothing else", got, tokenOwnerLogin)
	}
	if got := resp.Header.Get("X-Auth-Request-Auth-Method"); got != "access_token" {
		t.Errorf("auth-method header is %q; an application that wants to treat "+
			"automation differently has only this to go on", got)
	}
}

// TestRevokedAccessTokenStopsWorking.
//
// At read time, on the next request, like session revocation — never by
// waiting for something cached to expire (ADR 0004). A credential that keeps
// working after it has been withdrawn is the reason people distrust bearer
// tokens.
func TestRevokedAccessTokenStopsWorking(t *testing.T) {
	token := tokenFor(t)

	resp := bearerRequest(t, http.MethodGet, "/api/auth/me", token, nil)
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token did not work before revocation: %d", resp.StatusCode)
	}

	// Find its id, then withdraw it.
	listing := cardinalCLI(t, "token", "list", tokenOwnerLogin)
	var id string
	for _, line := range strings.Split(listing, "\n") {
		if strings.Contains(line, "e2e") {
			id = strings.Fields(line)[0]
			break
		}
	}
	if id == "" {
		t.Fatalf("could not find the token in: %s", listing)
	}
	cardinalCLI(t, "token", "revoke", tokenOwnerLogin, id)

	after := bearerRequest(t, http.MethodGet, "/api/auth/me", token, nil)
	defer drain(after)
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d after revocation, want 401 — the token outlived being "+
			"withdrawn", after.StatusCode)
	}
}
