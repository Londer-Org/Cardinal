package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Access tokens through the API their owner actually reaches.
//
// accesstoken_test.go covers what a token *is* — a weaker credential that
// cannot administer. This covers who may create and destroy one, which is a
// different question and the one the console raised: until now the only way to
// get a token was `cardinal token create`, so the one credential belonging to a
// person was the one credential that person could not obtain without asking an
// administrator with database access.
//
// The design answer is that these three routes are self-service and nothing
// else. There is no administrative variant, on purpose: an administrator able
// to mint somebody's token could act as them, and no log would distinguish it
// from the person themselves. That claim is only worth anything if it is
// tested, so most of what follows is about the boundary rather than the
// feature.

// tokenUser seeds an ordinary, non-administrative account with a session.
//
// Ordinary deliberately. Self-service must work for somebody with no privileges
// at all — a token is not an administrative object — and the isolation tests
// below mean nothing if both parties are administrators who could reach each
// other's things by another route anyway.
func tokenUser(t *testing.T, login, token string) (*http.Client, string) {
	t.Helper()

	seedSQL(t, `INSERT INTO entities (type, name, display_name)
	            VALUES ('user', '`+login+`', 'Token Self-service')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)

	// Never an administrator. If a previous run granted it, take it back rather
	// than assume a clean database.
	seedSQL(t, `DELETE FROM group_members
	             WHERE group_id = '`+adminGroupID+`'
	               AND member_id = (SELECT id FROM entities WHERE name = '`+login+`')`)

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

type createdToken struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

// createToken posts and reports the status, refusals included.
//
// Deliberately not the shared postJSON helper, which calls t.Fatal on anything
// that is not a success — fine for the paths that must work, useless for a test
// whose subject is what gets turned away.
func createToken(t *testing.T, c *http.Client, csrf string, body any) (createdToken, int) {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+"/api/tokens", bytes.NewReader(encoded))
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

	var out createdToken
	if resp.StatusCode == http.StatusCreated {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return out, resp.StatusCode
}

func listTokens(t *testing.T, c *http.Client) []struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
} {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/tokens", "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing tokens returned %d", resp.StatusCode)
	}

	var body struct {
		Tokens []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Prefix string `json:"prefix"`
		} `json:"tokens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Tokens
}

func deleteToken(t *testing.T, c *http.Client, csrf, id string) int {
	t.Helper()

	req, err := http.NewRequest(http.MethodDelete, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+"/api/tokens/"+id, nil)
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

// TestATokenCreatedInTheConsoleActuallyWorks.
//
// The obvious thing, which is worth asserting first because everything below is
// a refusal — and five passing refusals mean nothing if the feature is broken.
// The value returned is used as a credential rather than merely inspected: a
// console that shows a person a string that does not authenticate is worse than
// no console.
func TestATokenCreatedInTheConsoleActuallyWorks(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-tokens", "e2e-tokens-session-with-plenty-of-entropy-01234567")

	created, status := createToken(t, c, csrf,
		map[string]any{"name": "nightly export", "days": 30})
	if status != http.StatusCreated {
		t.Fatalf("creating a token returned %d, want 201", status)
	}
	if created.Token == "" {
		t.Fatal("no token in the response — the one moment it is ever returned")
	}

	resp := bearerRequest(t, http.MethodGet, "/api/auth/me", created.Token, nil)
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the value the console showed does not authenticate: %d", resp.StatusCode)
	}

	var me struct {
		Login      string `json:"login"`
		AuthMethod string `json:"authMethod"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.Login != "e2e-tokens" {
		t.Errorf("the token authenticates as %q, not the person who created it", me.Login)
	}
	if me.AuthMethod != "access_token" {
		t.Errorf("authMethod is %q, want access_token", me.AuthMethod)
	}
}

// TestTheTokenValueIsReturnedExactlyOnce.
//
// Only a hash is stored, so the listing cannot show the value even if somebody
// later decided it should. Asserted against the listing rather than trusted
// from the schema, because "we only store a hash" is a claim about a whole code
// path and a JSON field is easy to add by accident.
func TestTheTokenValueIsReturnedExactlyOnce(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-tokens-once", "e2e-tokens-once-session-with-entropy-0123456789ab")

	created, status := createToken(t, c, csrf, map[string]any{"name": "once", "days": 30})
	if status != http.StatusCreated {
		t.Fatalf("creating a token returned %d", status)
	}

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/tokens", "application/json")
	defer drain(resp)

	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" {
		t.Fatal("nothing was returned to look for")
	}
	if strings.Contains(string(raw), created.Token) {
		t.Fatal("the listing contains the token value — a database read now yields " +
			"a usable credential, which is the thing hashing exists to prevent")
	}
}

// TestOnePersonCannotSeeOrRevokeAnothersTokens.
//
// The whole boundary in one test. Both accounts are ordinary users, so nothing
// here passes because of a privilege difference.
//
// The revocation half matters more than the listing half: an id is a UUID
// somebody might obtain from a log, a screenshot, or a shared terminal, and
// revoking a colleague's production token is a denial of service that looks
// like the token expiring.
func TestOnePersonCannotSeeOrRevokeAnothersTokens(t *testing.T) {
	alice, aliceCSRF := tokenUser(t, "e2e-tokens-alice",
		"e2e-tokens-alice-session-with-entropy-0123456789abc")
	bob, bobCSRF := tokenUser(t, "e2e-tokens-bob",
		"e2e-tokens-bob-session-with-entropy-0123456789abcde")

	hers, status := createToken(t, alice, aliceCSRF,
		map[string]any{"name": "alice production", "days": 30})
	if status != http.StatusCreated {
		t.Fatalf("creating returned %d", status)
	}

	for _, got := range listTokens(t, bob) {
		if got.ID == hers.ID {
			t.Fatal("one person's listing contains another's token")
		}
	}

	if code := deleteToken(t, bob, bobCSRF, hers.ID); code != http.StatusNotFound {
		t.Fatalf("revoking somebody else's token returned %d, want 404", code)
	}

	// Not merely refused — still working. A 404 that revoked it anyway would
	// pass the assertion above and be the exact bug this guards against.
	resp := bearerRequest(t, http.MethodGet, "/api/auth/me", hers.Token, nil)
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the token was refused (%d) after somebody else was told 404 — "+
			"it was revoked despite the refusal", resp.StatusCode)
	}
}

// TestAnAdministratorHasNoWayToMintSomebodyElseAToken.
//
// The design decision, asserted rather than merely documented. The subject
// comes from the session and the request body has no say — so an administrator
// sending one gets a token for themselves, not for the person they named.
//
// Sending a field the server does not read is a strange-looking test, and it is
// the right one: the failure it guards against is somebody later adding a
// `subject` field to the request struct because it seems convenient, at which
// point every administrator silently gains the ability to act as anybody with
// nothing in the log to show it.
func TestAnAdministratorHasNoWayToMintSomebodyElseAToken(t *testing.T) {
	admin, adminCSRF := adminClient(t)
	victim, _ := tokenUser(t, "e2e-tokens-victim",
		"e2e-tokens-victim-session-with-entropy-0123456789ab")

	victimID := seedQuery(t, `SELECT id FROM entities WHERE name = 'e2e-tokens-victim'`)
	if victimID == "" {
		t.Fatal("could not find the account")
	}

	created, status := createToken(t, admin, adminCSRF, map[string]any{
		"name":      "on behalf of somebody else",
		"days":      30,
		"subject":   victimID,
		"subjectId": victimID,
		"login":     "e2e-tokens-victim",
	})
	if status != http.StatusCreated {
		t.Fatalf("creating returned %d", status)
	}

	resp := bearerRequest(t, http.MethodGet, "/api/auth/me", created.Token, nil)
	defer drain(resp)

	var me struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me.Login == "e2e-tokens-victim" {
		t.Fatal("an administrator minted a token that authenticates as somebody " +
			"else — every action it takes is logged as that person")
	}
	if me.Login != tokenOwnerLogin {
		t.Fatalf("the token belongs to %q; it should belong to its creator", me.Login)
	}

	// And the victim's own listing does not contain it, which is what they
	// would look at to find out.
	for _, got := range listTokens(t, victim) {
		if got.ID == created.ID {
			t.Fatal("a token appeared in somebody's list that they did not create")
		}
	}
}

// TestRevokingYourOwnTokenStopsItImmediately.
//
// At read time on the next request, not when something cached expires. The
// console's revoke button is the one people will reach for when a token leaks,
// and "it stops working in a few minutes" is not an answer at that moment.
func TestRevokingYourOwnTokenStopsItImmediately(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-tokens-revoke",
		"e2e-tokens-revoke-session-with-entropy-0123456789ab")

	created, status := createToken(t, c, csrf, map[string]any{"name": "leaked", "days": 30})
	if status != http.StatusCreated {
		t.Fatalf("creating returned %d", status)
	}

	before := bearerRequest(t, http.MethodGet, "/api/auth/me", created.Token, nil)
	drain(before)
	if before.StatusCode != http.StatusOK {
		t.Fatalf("the token did not work before revocation: %d", before.StatusCode)
	}

	if code := deleteToken(t, c, csrf, created.ID); code != http.StatusNoContent {
		t.Fatalf("revoking returned %d, want 204", code)
	}

	after := bearerRequest(t, http.MethodGet, "/api/auth/me", created.Token, nil)
	defer drain(after)
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d after revocation, want 401", after.StatusCode)
	}
}

// TestATokenCannotBeAskedToLastForever.
//
// The console offers a year at most, but the console is a client like any
// other. A lifetime is a security property and belongs on the server.
func TestATokenCannotBeAskedToLastForever(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-tokens-ttl",
		"e2e-tokens-ttl-session-with-entropy-0123456789abcde")

	for _, tc := range []struct {
		name string
		body map[string]any
		want int
	}{
		{"a decade", map[string]any{"name": "forever", "days": 3650}, http.StatusBadRequest},
		{"no name", map[string]any{"name": "   ", "days": 30}, http.StatusBadRequest},
		{"a year exactly", map[string]any{"name": "a year", "days": 365}, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, status := createToken(t, c, csrf, tc.body); status != tc.want {
				t.Fatalf("got %d, want %d", status, tc.want)
			}
		})
	}
}

// TestATokenCannotTouchTheCredentialsThatAuthenticateItsOwner.
//
// Written while building the console, and it failed — which is why it covers
// the whole self-service surface rather than only the routes that prompted it.
//
// The state of the world it found: a token could POST /api/recovery/codes and
// read back ten account-recovery credentials, invalidating its owner's in the
// same statement. It could begin registering a passkey. It could revoke the
// owner's. And it could mint its own successor, so revoking a leaked token
// accomplished nothing at all.
//
// ADR 0018 said this was impossible — a token is never device-bound, and the
// policy forbidding dangerous actions turns on exactly that. The claim was true
// of every route that asks Cedar and these routes never did, because there is no
// resource to authorize against, only the caller's own account. A property that
// holds "for rules nobody has written yet" turned out not to hold for routes
// nobody had thought about.
//
// The refusal is a precondition on the credential now, in code, next to
// requireAuth. This test is what says so, and it is deliberately a table over
// the whole surface: the failure mode is a new self-service route added behind
// plain requireAuth, so the check has to be against the list rather than the
// three routes that started it.
func TestATokenCannotTouchTheCredentialsThatAuthenticateItsOwner(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-tokens-chain",
		"e2e-tokens-chain-session-with-entropy-0123456789abc")

	created, status := createToken(t, c, csrf, map[string]any{"name": "seed", "days": 30})
	if status != http.StatusCreated {
		t.Fatalf("creating returned %d", status)
	}

	for _, tc := range []struct {
		method, path, why string
	}{
		{
			http.MethodPost, "/api/recovery/codes",
			"mint account-recovery credentials, and destroy its owner's",
		},
		{
			http.MethodGet, "/api/recovery/codes/remaining",
			"count how many ways back into the account remain",
		},
		{
			http.MethodPost, "/api/credentials/register/begin",
			"start attaching a passkey of the holder's choosing",
		},
		{
			http.MethodPost, "/api/credentials/register/finish",
			"finish attaching one",
		},
		{
			http.MethodGet, "/api/credentials",
			"enumerate the passkeys to know what to revoke",
		},
		{
			http.MethodDelete, "/api/credentials/" + created.ID,
			"lock the owner out of their own account",
		},
		{
			http.MethodGet, "/api/tokens",
			"see what other tokens exist to go after",
		},
		{
			http.MethodPost, "/api/tokens",
			"mint its own successor and outlive being revoked",
		},
		{
			http.MethodDelete, "/api/tokens/" + created.ID,
			"revoke tokens using only itself",
		},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp := bearerRequest(t, tc.method, tc.path, created.Token, nil)
			defer drain(resp)

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("got %d, want 403 — a token could %s", resp.StatusCode, tc.why)
			}
		})
	}
}

// TestAPasskeySessionStillReachesAllOfIt.
//
// The other half, and the one that makes the test above worth anything: a
// refusal that also refuses the legitimate caller is not a security property,
// it is an outage. Same routes, same person, a session instead of a token.
func TestAPasskeySessionStillReachesAllOfIt(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-tokens-session",
		"e2e-tokens-session-with-entropy-0123456789abcdefgh")

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/credentials"},
		{http.MethodGet, "/api/recovery/codes/remaining"},
		{http.MethodGet, "/api/tokens"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp := request(t, c, tc.method, hostCardinal, tc.path, "application/json")
			defer drain(resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("got %d, want 200 — the fix locked out the person it protects",
					resp.StatusCode)
			}
		})
	}

	// And a mutation, since the reads could pass while a write path was broken.
	var codes struct {
		Codes []string `json:"codes"`
	}
	resp := postJSON(t, c, "/api/recovery/codes", csrf, map[string]any{}, &codes) //nolint:bodyclose // the helper drains and closes it; bodyclose cannot see through the call
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("generating recovery codes returned %d", resp.StatusCode)
	}
	if len(codes.Codes) == 0 {
		t.Fatal("no recovery codes came back")
	}
}
