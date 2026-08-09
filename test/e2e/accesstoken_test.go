package e2e

import (
	"encoding/json"
	"io"
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

	// Every scope, deliberately. These tests are about what *policy* refuses a
	// token — administration, SSH certificates, credential self-service — and a
	// narrow scope would refuse them first, for a different reason, and the
	// assertions would pass while proving nothing.
	out := cardinalCLI(t, "token", "create", tokenOwnerLogin, "-name", "e2e",
		"-for", "1h", "-scope", "identity,applications,profile,decisions,policy")
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

	req, err := http.NewRequest(method, origin(hostCardinal)+path, nil) //nolint:noctx // bounded by client timeout
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

// protectedIdentity is what the application behind Traefik reports it received.
type protectedIdentity struct {
	UserID      string   `json:"userId"`
	Login       string   `json:"login"`
	Groups      []string `json:"groups"`
	GroupIDs    []string `json:"groupIds"`
	AuthMethod  string   `json:"authMethod"`
	DeviceBound bool     `json:"deviceBound"`
	Policy      string   `json:"policy"`
}

// tokenIdentityAtProtectedApp asks the application what a token-bearing request
// looks like by the time it arrives.
//
// Through Traefik, rather than by calling /api/auth/verify with hand-written
// X-Forwarded-* headers. Two things were wrong with doing that, and both hid a
// real defect:
//
// Traefik overwrites X-Forwarded-Host with the host actually being requested,
// so a test that set it to app.cardinal.test was in fact asking about
// id.cardinal.test. That went unnoticed for as long as the answer did not
// depend on the hostname — which it did not, because forwardAuth classified
// every host identically and permitted them all.
//
// And a response header Cardinal sets only reaches an application if it is
// listed in authResponseHeaders. Reading the header off Cardinal's own response
// skips the one step that can drop it, which is how X-Auth-Request-Group-Ids
// came to be emitted on every request, asserted by a passing test, and never
// once delivered to anything.
func tokenIdentityAtProtectedApp(t *testing.T) protectedIdentity {
	t.Helper()
	token := tokenFor(t)

	req, err := http.NewRequest(http.MethodGet, //nolint:noctx // bounded by client timeout
		origin(hostProtected)+"/whoami.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // reported by the failure that follows
		t.Fatalf("got %d — a token was refused access a session would have been "+
			"granted, which leaves the proxy bypass as the only option: %s",
			resp.StatusCode, body)
	}

	var identity protectedIdentity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		t.Fatal(err)
	}
	return identity
}

// TestAccessTokenReachesAProtectedApplication.
//
// The point of the whole thing. A script presents a token to the same
// forwardAuth endpoint a browser uses, and the application behind it receives
// the same identity headers — so it needs no idea that tokens exist, and the
// proxy needs no rule routing API traffic around the check.
func TestAccessTokenReachesAProtectedApplication(t *testing.T) {
	identity := tokenIdentityAtProtectedApp(t)

	if identity.Login != tokenOwnerLogin {
		t.Errorf("login = %q, want %q — the application behind the proxy reads "+
			"this and nothing else", identity.Login, tokenOwnerLogin)
	}
	if identity.AuthMethod != "access_token" {
		t.Errorf("authMethod = %q; an application that wants to treat automation "+
			"differently has only this to go on", identity.AuthMethod)
	}
	if identity.DeviceBound {
		t.Error("a token reported itself device-bound; ADR 0018 rests on it " +
			"never being one")
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

// TestIdentityHeadersCarryStableGroupIdentifiers.
//
// An application deciding what somebody may do has to key on something Cardinal
// will not change underneath it. Group names are mutable attributes by design
// (ADR 0002) — that is the whole objection to LDAP's DN — so a permission model
// written against the string "aura-admins" is the same mistake one layer out.
//
// Nothing can rename a group today, which is exactly why this is worth fixing
// now: applications should be coupling to the stable thing *before* rename
// exists, not migrating afterwards.
func TestIdentityHeadersCarryStableGroupIdentifiers(t *testing.T) {
	identity := tokenIdentityAtProtectedApp(t)

	if len(identity.Groups) == 0 {
		t.Fatal("no groups reached the application at all")
	}
	if len(identity.GroupIDs) == 0 {
		t.Fatal("no group identifiers reached the application — an application " +
			"has nothing stable to key on. If Cardinal sets the header, the " +
			"missing piece is X-Auth-Request-Group-Ids in authResponseHeaders " +
			"in examples/traefik/dynamic.yml")
	}

	nameCount := len(identity.Groups)
	idCount := len(identity.GroupIDs)
	if nameCount != idCount {
		t.Fatalf("%d names but %d ids — they must line up, or an application "+
			"cannot map one to the other", nameCount, idCount)
	}

	// Identifiers, not names repeated under a second header.
	for _, id := range identity.GroupIDs {
		if len(id) != 36 || strings.Count(id, "-") != 4 {
			t.Errorf("group id %q is not a UUID", id)
		}
	}
}

// TestAScopeNarrowsWhatATokenMayAttempt.
//
// The gap this closes. A token authenticates its owner and is never
// device-bound, so policy refuses it administration and SSH certificates
// (ADR 0018) — but everything the owner can do *without* a hardware key was
// still on the table: the decision log, the active policy set, the owner's own
// profile, and every application they can reach. For a credential living in a
// CI variable that is a grant nobody would write down on purpose.
//
// A scope only narrows. Policy still decides, and the token still cannot exceed
// its owner — so the check below is what a token was *issued for*, a question
// Cedar cannot ask because it sees a principal and not the credential.
func TestAScopeNarrowsWhatATokenMayAttempt(t *testing.T) {
	adminClient(t)

	out := cardinalCLI(t, "token", "create", tokenOwnerLogin, "-name", "e2e-narrow",
		"-for", "1h", "-scope", "identity")
	var narrow string
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "crd_pat_") {
			narrow = field
		}
	}
	if narrow == "" {
		t.Fatalf("no token in output: %s", out)
	}

	// The scope it has.
	resp := bearerRequest(t, http.MethodGet, "/api/auth/me", narrow, nil)
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("identity scope did not reach /api/auth/me: %d", resp.StatusCode)
	}

	// The ones it does not, each of which the owner could reach with a passkey.
	for _, tc := range []struct{ method, path, scope string }{
		{http.MethodGet, "/api/decisions", "decisions"},
		{http.MethodGet, "/api/policy", "policy"},
		{http.MethodPatch, "/api/auth/me", "profile"},
	} {
		t.Run(tc.scope, func(t *testing.T) {
			refused := bearerRequest(t, tc.method, tc.path, narrow, nil)
			body, _ := io.ReadAll(refused.Body) //nolint:errcheck // reported by the assertion below
			drain(refused)

			if refused.StatusCode != http.StatusForbidden {
				t.Fatalf("got %d, want 403 — a token reached %s without the %s scope",
					refused.StatusCode, tc.path, tc.scope)
			}
			// Named, because a 403 in a pipeline log at 3am that reads as "this
			// account lost access" sends somebody to the directory rather than
			// to the token.
			if !strings.Contains(string(body), tc.scope) {
				t.Errorf("the refusal does not name the missing scope: %s", body)
			}
		})
	}
}

// TestATokenWithNoScopeIsRefusedAtIssue.
//
// Rather than issued and refused everything at use. A token with a missing or
// misspelled scope authenticates and is then turned away wherever it is used —
// usually an unattended pipeline, hours later, with a message about permissions
// rather than about spelling.
func TestATokenWithNoScopeIsRefusedAtIssue(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-noscope", "e2e-noscope-session-with-plenty-of-entropy-0123")

	_, status := createToken(t, c, csrf, map[string]any{"name": "unscoped", "days": 30})
	if status != http.StatusBadRequest {
		t.Fatalf("creating a token with no scope returned %d, want 400", status)
	}

	_, status = createToken(t, c, csrf,
		map[string]any{"name": "typo", "days": 30, "scopes": []string{"identty"}})
	if status != http.StatusBadRequest {
		t.Fatalf("a misspelled scope returned %d, want 400", status)
	}
}
