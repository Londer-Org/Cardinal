package e2e

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

// What an application is told, against what Cardinal decides.
//
// Against the running stack because the two halves live in different places: a
// Cedar evaluation over the full closure, and a header written afterwards from
// a filtered set. A unit test can hold either and not the seam.

// TestNarrowingWhatAnApplicationSeesDoesNotChangeWhoMayReachIt.
//
// The invariant the whole feature rests on (ADR 0032). forwardauth.go resolves
// one subject and uses it three times — policy input, decision log, headers —
// so narrowing that variable is the obvious way to implement filtering and
// would silently change what Cardinal decides.
//
// Both directions are real. A permit keyed on group membership would start
// refusing people who are members; a forbid keyed on one would stop matching
// and admit somebody it exists to refuse. This asserts the request is admitted
// identically while the disclosure changes underneath it.
func TestNarrowingWhatAnApplicationSeesDoesNotChangeWhoMayReachIt(t *testing.T) {
	t.Cleanup(restoreProjection)

	cardinalCLI(t, "app", "groups", "mode", "protected-app", "all")
	wide := tokenIdentityAtProtectedApp(t)
	if len(wide.Groups) == 0 {
		t.Fatal("the fixture is not telling the application about any groups, so " +
			"this test cannot tell filtering from an empty directory")
	}

	// protected-app owns no groups, so owned mode is the sharpest version of
	// the question: everything the application was told, withdrawn at once.
	cardinalCLI(t, "app", "groups", "mode", "protected-app", "owned")
	narrow := tokenIdentityAtProtectedApp(t)

	// Admitted either way. tokenIdentityAtProtectedApp fails the test on any
	// status but 200, so reaching here twice is the assertion — the person was
	// permitted before and after, by the same policy, on the same membership.
	if len(narrow.Groups) != 0 {
		t.Errorf("the application was still told about %d group(s) after being "+
			"narrowed to the ones it owns, and it owns none", len(narrow.Groups))
	}
	if len(narrow.GroupIDs) != 0 {
		t.Errorf("group identifiers survived the narrowing: %v", narrow.GroupIDs)
	}
}

// TestAnAllowedGroupReachesTheApplicationAgain is the escape hatch, end to end.
//
// Without it the only way to tell an application about a group is to give it
// one, which is not always somebody's to do — the group may predate the
// application by years.
func TestAnAllowedGroupReachesTheApplicationAgain(t *testing.T) {
	t.Cleanup(func() {
		cliBackground("app", "groups", "disallow", "protected-app", "engineers")
		restoreProjection()
	})

	// The group the seeded user is actually in, so the claim has something to
	// carry. Granted here rather than assumed: the suite reseeds.
	tryCardinalCLI(t, "grant", "engineers", tokenOwnerLogin, "-reason", "projection e2e")
	cardinalCLI(t, "app", "groups", "mode", "protected-app", "owned")

	before := tokenIdentityAtProtectedApp(t)
	for _, g := range before.Groups {
		if g == "engineers" {
			t.Fatal("engineers reached the application before it was allowed, so " +
				"this proves nothing about allowing it")
		}
	}

	cardinalCLI(t, "app", "groups", "allow", "protected-app", "engineers")
	after := tokenIdentityAtProtectedApp(t)

	found := false
	for _, g := range after.Groups {
		if g == "engineers" {
			found = true
		}
	}
	if !found {
		t.Errorf("engineers was allowed and still did not reach the application; "+
			"it was told about %v", after.Groups)
	}
}

// TestASystemGroupIsNeverTold.
//
// directory-admins is authority inside Cardinal. An application branching on it
// would be treating a Cardinal internal as one of its own roles, and an
// application that could be granted sight of it would make that a supported
// integration rather than a mistake.
func TestASystemGroupIsNeverTold(t *testing.T) {
	t.Cleanup(restoreProjection)

	cardinalCLI(t, "app", "groups", "mode", "protected-app", "owned")

	// Run directly rather than through cardinalCLI, which fails the test on a
	// non-zero exit — and a refusal is the result being asserted.
	full := append([]string{
		"compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "cardinal", "cardinal",
	}, "app", "groups", "allow", "protected-app", "directory-admins")
	out, err := exec.CommandContext(t.Context(), "docker", full...).CombinedOutput()
	if err == nil {
		t.Fatal("allowing a system group succeeded")
	}
	if !strings.Contains(string(out), "authority inside Cardinal") {
		t.Errorf("refused without saying why: %s", out)
	}
}

// restoreProjection puts the fixture back for whatever runs next.
//
// Not through cardinalCLI: a t.Cleanup runs after t.Context() is cancelled, so
// every command issued from one dies with "context canceled". The tests do not
// depend on this — each sets the mode it needs — but leaving the stack narrowed
// would make the next run of an unrelated header test fail confusingly.
func restoreProjection() {
	cliBackground("app", "groups", "mode", "protected-app", "all")
}

func cliBackground(args ...string) {
	full := append([]string{
		"compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "cardinal", "cardinal",
	}, args...)
	_ = exec.Command("docker", full...).Run() //nolint:errcheck,noctx // best effort cleanup
}

// TestEveryTokenCarriesOnlyWhatTheApplicationMayBeTold.
//
// A relying party is handed two JWTs and both can carry groups, assembled by
// two different storage methods: the id_token through SetUserinfoFromScopes,
// the access token through GetPrivateClaimsFromScopes. Only the first was
// narrowed, so a projection filtered the forwardAuth header and the userinfo
// response while the access token still carried the whole closure — and
// Cardinal's access tokens are JWTs deliberately, so anything in one is
// readable by every resource server behind that relying party.
//
// Both are asserted here because the pair is the point: a projection that
// holds for one token and not the other is not a projection.
func TestEveryTokenCarriesOnlyWhatTheApplicationMayBeTold(t *testing.T) {
	t.Cleanup(func() { cliBackground("app", "groups", "mode", "e2e-client", "all") })

	// e2e-user is who establishSession signs in as, and the seed leaves them in
	// no groups at all — so without this the wide case and the narrow case are
	// both empty and the test passes while proving nothing.
	tryCardinalCLI(t, "grant", "engineers", "e2e-user", "-reason", "projection e2e")

	cardinalCLI(t, "app", "groups", "mode", "e2e-client", "all")
	wideAccess, wideID := tokenGroups(t)
	if len(wideAccess) == 0 || len(wideID) == 0 {
		t.Fatalf("a token carried no groups before anything was narrowed "+
			"(access %v, id %v), so this test cannot tell a narrowed claim "+
			"from an empty directory", wideAccess, wideID)
	}

	// e2e-client owns no groups, so `owned` withdraws all of them at once.
	cardinalCLI(t, "app", "groups", "mode", "e2e-client", "owned")
	narrowAccess, narrowID := tokenGroups(t)
	if len(narrowAccess) != 0 {
		t.Errorf("the access token still carried %v after the application was "+
			"narrowed to the groups it owns, and it owns none", narrowAccess)
	}
	if len(narrowID) != 0 {
		t.Errorf("the id_token still carried %v after the application was "+
			"narrowed to the groups it owns, and it owns none", narrowID)
	}
}

// tokenGroups drives an authorization for the `groups` scope and returns the
// claim out of both tokens the exchange returns.
//
// The payloads are read without verifying the signature, which would be wrong
// in a client and is right here: the assertion is about what Cardinal put in
// the tokens, and oidc_test.go already covers that they verify.
func tokenGroups(t *testing.T) (access, id []string) {
	t.Helper()

	clientID := seededClientID(t)
	c := client(t)
	code, verifier := authorizeAs(t, c, clientID, "openid groups")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {origin(hostRP) + "/callback"},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("token exchange failed with %d: %s", resp.StatusCode, body)
	}

	var token struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}
	return groupsClaim(t, "access token", token.AccessToken),
		groupsClaim(t, "id_token", token.IDToken)
}

// groupsClaim reads the groups out of a JWT payload.
func groupsClaim(t *testing.T, which, jwt string) []string {
	t.Helper()

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("the %s is not a JWT, so this test is checking the wrong "+
			"thing: %q", which, jwt)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding the %s payload: %v", which, err)
	}

	var claims struct {
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parsing the %s payload: %v", which, err)
	}
	return claims.Groups
}

// seededClientID reads the client id of the relying party the Makefile seeds,
// which is registered with the `groups` scope this test needs.
func seededClientID(t *testing.T) string {
	t.Helper()

	repointClient(t, "e2e-client")
	out, err := exec.CommandContext(t.Context(), "docker", "compose",
		"-f", "../../examples/compose.yml", "exec", "-T", "postgres",
		"psql", "-U", "cardinal", "-d", "cardinal", "-tAc",
		"SELECT client_id FROM oidc_clients c JOIN entities e ON e.id = c.entity_id "+
			"WHERE e.name = 'e2e-client'").Output()
	if err != nil {
		t.Fatalf("reading the seeded client id: %v", err)
	}
	id := strings.TrimSpace(string(out))
	if id == "" {
		t.Fatal("the seeded relying party has no client_id")
	}
	return id
}
