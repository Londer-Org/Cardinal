package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Policy versions, and rolling back to one.
//
// The point of every test here is that activating changes what is *enforced*,
// not what a row says. Until this work, ReloadPolicy had exactly one caller —
// startup — so `cardinal policy activate` updated a column and the running
// server carried on evaluating the set it had loaded when it booted. The CLI
// admitted it ("restart the server, or it keeps serving the previous set"),
// which made it a documented limitation rather than a surprise, and made
// rolling back a bad policy a two-step operation whose second step needed a
// shell on the server.
//
// A rollback button on top of that would have been worse than none: it reports
// success and leaves the old rules in force.

type policyVersionsBody struct {
	Live     int64 `json:"live"`
	Versions []struct {
		Version     int64  `json:"version"`
		Description string `json:"description"`
		Active      bool   `json:"active"`
		Live        bool   `json:"live"`
		PolicyCount int    `json:"policyCount"`
		Invalid     bool   `json:"invalid"`
	} `json:"versions"`
}

func policyVersions(t *testing.T, c *http.Client) policyVersionsBody {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/policy/versions", "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing policy versions returned %d", resp.StatusCode)
	}

	var out policyVersionsBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// publishOnly loads a policy set without activating it, and returns its version.
//
// Distinct from publishPolicy, which publishes, activates and restarts the
// container. Restarting is exactly what these tests must not do — the claim
// under test is that activation takes effect *without* one.
func publishOnly(t *testing.T, document, description string) int64 {
	t.Helper()

	tmp, err := os.CreateTemp(t.TempDir(), "policy-*.cedar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.WriteString(document); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	// The container runs as nonroot and docker cp preserves the mode, so a
	// 0600 temp file lands unreadable inside.

	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.CommandContext(t.Context(), "docker", "cp", tmp.Name(),
		containerID(t)+":/tmp/e2e-versioned.cedar").CombinedOutput(); err != nil {
		t.Fatalf("copying policy: %v\n%s", err, out)
	}

	out := cardinalCLI(t, "policy", "publish", "/tmp/e2e-versioned.cedar",
		"-description", description)

	// "published version N — ..." is the line; the number is what everything
	// after this needs.
	for _, field := range strings.Fields(out) {
		if n, err := strconv.ParseInt(field, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	t.Fatalf("no version number in: %s", out)
	return 0
}

func activateVersion(t *testing.T, c *http.Client, csrf string, version int64) int {
	t.Helper()

	req := jsonRequest(t, http.MethodPost,
		"/api/policy/versions/"+strconv.FormatInt(version, 10)+"/activate", csrf, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)
	return resp.StatusCode
}

// TestRollingBackChangesWhatIsEnforcedWithoutARestart.
//
// The test this whole piece of work exists for. A version is published that
// removes application access, activated through the API, and the *behaviour* is
// checked — not the row, not the reported version number, but whether a request
// that used to be allowed is now refused. Then back again.
//
// Nothing restarts. If ReloadPolicy still had one caller this would fail on the
// first assertion, which is the only reason to write it this way round.
func TestRollingBackChangesWhatIsEnforcedWithoutARestart(t *testing.T) {
	defer publishPolicy(t, permissivePolicy())()

	admin, csrf := adminClient(t)
	before := policyVersions(t, admin)

	// A set identical to the fixture except that it grants no application
	// access at all. Cedar is default-deny, so removing the permit is enough.
	restrictive := publishOnly(t, restrictivePolicy(), "e2e rollback: no app access")

	c := client(t)
	withSession(t, c)

	if code := appAccess(t, c); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("application access was already refused (%d) — the rest of this "+
			"test cannot distinguish a working rollback from a broken fixture", code)
	}

	if code := activateVersion(t, admin, csrf, restrictive); code != http.StatusOK {
		t.Fatalf("activating returned %d", code)
	}

	// No restart, no sleep. The server that handled the activation reloaded its
	// own engine before replying.
	if code := appAccess(t, c); code == http.StatusNoContent || code == http.StatusOK {
		t.Fatal("application access is still granted after activating a set that " +
			"does not grant it — the row changed and nothing else did")
	}

	// And back, which is the direction somebody actually takes at 3am.
	if code := activateVersion(t, admin, csrf, before.Live); code != http.StatusOK {
		t.Fatalf("rolling forward returned %d", code)
	}
	if code := appAccess(t, c); code != http.StatusNoContent && code != http.StatusOK {
		t.Fatalf("access was not restored by rolling back (%d)", code)
	}
}

// TestANodeThatDidNotServeTheActivationCatchesUp.
//
// The other half. One server reloading its own engine is not enough — a fleet
// has several, and only one of them handles the button press. The rest have to
// notice on their own, which is what the watcher does.
//
// Exercised through the CLI, because that is a change made entirely outside any
// server: no HTTP request, no in-process reload, just a row. If the watcher
// were not running this would never converge.
func TestANodeThatDidNotServeTheActivationCatchesUp(t *testing.T) {
	defer publishPolicy(t, permissivePolicy())()

	admin, _ := adminClient(t)
	before := policyVersions(t, admin)

	target := publishOnly(t, restrictivePolicy(), "e2e watcher pickup")
	cardinalCLI(t, "policy", "activate", strconv.FormatInt(target, 10))

	// Generous against the ten-second interval: the tick has an arbitrary phase
	// relative to this line, so the worst case is a full interval plus the time
	// to compile and swap.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if policyVersions(t, admin).Live == target {
			// Restore before returning, and through the CLI again so this test
			// leaves nothing depending on the API path.
			cardinalCLI(t, "policy", "activate", strconv.FormatInt(before.Live, 10))
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("version %d was activated and no server picked it up — a change made "+
		"outside a request is invisible until a restart", target)
}

// TestAVersionThatDoesNotCompileCannotBeActivated.
//
// Activating one leaves every node unable to load it, and each keeps serving
// whatever it already had — so the fleet ends up split across policy sets with
// nothing on screen to say so, and the only symptom is that a change did not
// take effect. Refusing early turns that into a failed button press.
func TestAVersionThatDoesNotCompileCannotBeActivated(t *testing.T) {
	defer publishPolicy(t, permissivePolicy())()

	admin, csrf := adminClient(t)
	before := policyVersions(t, admin)

	// `policy publish` compiles before storing, so a broken document cannot be
	// published through it. Written straight to the table instead, which is the
	// state a database restored from an older release could genuinely be in —
	// the engine changed under a document that compiled when it was published.
	//
	// version is GENERATED ALWAYS AS IDENTITY, so it comes back rather than
	// going in.
	raw := seedQuery(t, `INSERT INTO policy_versions (document, digest, description)
	                     VALUES ('permit (principal', sha256('broken'::bytea),
	                             'e2e deliberately broken')
	                  RETURNING version`)
	// psql prints the returned row and then the command tag, so "172\nINSERT 0 1"
	// is a successful insert rather than a malformed one.
	broken, err := strconv.ParseInt(strings.SplitN(raw, "\n", 2)[0], 10, 64)
	if err != nil {
		t.Fatalf("no version came back from the insert: %q", raw)
	}

	if code := activateVersion(t, admin, csrf, broken); code != http.StatusBadRequest {
		t.Fatalf("activating an uncompilable version returned %d, want 400", code)
	}
	if live := policyVersions(t, admin).Live; live != before.Live {
		t.Fatalf("the live version changed to %d despite the refusal", live)
	}

	// And it is flagged in the listing, because it looks like every other row.
	for _, v := range policyVersions(t, admin).Versions {
		if v.Version == broken && !v.Invalid {
			t.Fatal("a version that does not compile is not marked as such — " +
				"it is the one nobody must roll back to")
		}
	}
}

// TestPolicyVersionsNeedTheBroadTier.
//
// Not the people tier. Activating a set decides every question Cardinal
// answers, including who may activate the next one, so it must not come with
// managing accounts.
func TestPolicyVersionsNeedTheBroadTier(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-policy-outsider",
		"e2e-policy-outsider-with-entropy-0123456789abc")

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/policy/versions"},
		{http.MethodGet, "/api/policy/versions/1"},
		{http.MethodPost, "/api/policy/versions/1/activate"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp, err := c.Do(jsonRequest(t, tc.method, tc.path, csrf, nil))
			if err != nil {
				t.Fatal(err)
			}
			defer drain(resp)

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("got %d, want 403", resp.StatusCode)
			}
		})
	}
}

// appAccess asks the forwardAuth endpoint the question an application asks.
// appAccess asks whether the protected application is reachable right now.
//
// Through Traefik at the application's own address, rather than by calling
// /api/auth/verify with X-Forwarded-* written by hand. Traefik overwrites
// X-Forwarded-Host with the host being requested, so the hand-written version
// was asking about id.cardinal.test while appearing to ask about the protected
// app — invisible for as long as forwardAuth treated every hostname the same,
// and wrong from the moment it stopped.
func appAccess(t *testing.T, c *http.Client) int {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		origin(hostProtected)+"/whoami.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)
	return resp.StatusCode
}

// The two sets these tests toggle between.
//
// Identical except for one rule: whether anybody may reach a web application
// through forwardAuth. That is the difference the behavioural assertions
// observe, and keeping everything else the same means a failure can only be
// about the rule that changed.
//
// Both keep the administration rules, and they have to. Activating a set that
// does not grant the caller administration is a one-way door — the endpoint
// that would roll it back is behind the rule the new set just removed. The
// console says so in as many words before anybody presses the button, and
// `cardinal policy activate` on the server stays the way out.
const adminRules = `
@id("directory-admins-may-administer")
permit (
    principal in Cardinal::Group::"00000000-0000-7000-8000-00000000ad11",
    action in [
        Cardinal::Action::"AdministerDirectory",
        Cardinal::Action::"ManageUsers",
        Cardinal::Action::"ManageApplications"
    ],
    resource
);

@id("admin-requires-fresh-device-bound-auth")
forbid (
    principal,
    action in [Cardinal::Action::"AdministerDirectory",
               Cardinal::Action::"ManageUsers",
               Cardinal::Action::"ManageApplications"],
    resource
)
unless {
    principal.deviceBound && principal.authAgeSeconds <= 300
};

@id("any-user-may-access-any-application")
permit (
    principal,
    action == Cardinal::Action::"AccessApplication",
    resource
);
`

// permissivePolicy grants web access to everything, unconditionally.
//
// Deliberately broader than the shipped rule, which permits an application only
// if it is in staff-apps. What these tests toggle is whether *a* permit exists,
// so the fixture should not also depend on the group membership of the seeded
// application: a failure would then have two possible causes and the assertion
// message would name the wrong one.
func permissivePolicy() string {
	return adminRules + `
@id("staff-web-access")
permit (
    principal,
    action == Cardinal::Action::"AccessURL",
    resource
);
`
}

// restrictivePolicy omits the web-access rule entirely.
//
// Omission rather than a forbid, because Cedar is default-deny and this is the
// shape a rollback actually has: an earlier set that simply did not contain the
// rule somebody added later.
func restrictivePolicy() string { return adminRules }

// TestAdminCanBuildARuleFromTheConsole.
//
// Composing policy without writing Cedar, through the API the console uses.
// The property worth asserting is not that a row changed but that the rule
// governs: it is published, activated, and the running server is enforcing it
// before the response comes back.
func TestAdminCanBuildARuleFromTheConsole(t *testing.T) {
	defer publishPolicy(t, permissivePolicy())()

	c, csrf := adminClient(t)
	const ruleID = "e2e-built-rule"

	// A group for it to name. A rule naming one that is not there never
	// matches, and this is the API refusing that rather than storing it.
	seedSQL(t, `UPDATE entities SET name = name || '-' || id WHERE name = 'e2e-built-group'`)
	postJSON(t, c, "/api/directory/groups", csrf, map[string]any{ //nolint:bodyclose // postJSON closes the body before returning
		"name": "e2e-built-group", "displayName": "Built by a test",
	}, nil)

	missing := postExpectingFailure(t, c, csrf, "/api/policy/rules", map[string]any{ //nolint:bodyclose // postExpectingFailure drains it
		"id": ruleID, "kind": "web-access",
		"principalGroup": "no-such-group-anywhere",
		"resourceGroup":  "e2e-built-group",
	})
	if missing.StatusCode != http.StatusBadRequest {
		t.Errorf("naming a group that does not exist returned %d, want 400 — "+
			"storing it would produce a rule that can never match, which "+
			"default-deny makes look like the rule working", missing.StatusCode)
	}

	var added struct {
		Version int64 `json:"version"`
	}
	postJSON(t, c, "/api/policy/rules", csrf, map[string]any{ //nolint:bodyclose // postJSON closes the body before returning
		"id": ruleID, "kind": "web-access",
		"principalGroup": "e2e-built-group",
		"resourceGroup":  "e2e-built-group",
	}, &added)
	if added.Version == 0 {
		t.Fatal("adding a rule did not publish a version")
	}

	// It is in the live set, described in words rather than in Cedar, and with
	// the group named rather than identified.
	found := false
	for _, rule := range listRules(t, c) {
		if rule.ID != ruleID {
			continue
		}
		found = true
		if !rule.Composable {
			t.Error("a rule the builder composed came back as hand-written; it " +
				"could then never be removed the way it was added")
		}
		if !strings.Contains(rule.Summary, "e2e-built-group") {
			t.Errorf("summary is %q — it should name the group, not identify it",
				rule.Summary)
		}
		if len(rule.Missing) != 0 {
			t.Errorf("a rule naming groups that exist reports %v missing", rule.Missing)
		}
	}
	if !found {
		t.Fatalf("%s was added and is not in the live set", ruleID)
	}

	// A guardrail is not removable from here. The step-up forbid is what makes
	// membership of directory-admins insufficient on its own.
	guardrail := requestWithCSRF(t, c, http.MethodDelete,
		"/api/policy/rules/admin-requires-fresh-device-bound-auth", csrf)
	drain(guardrail)
	if guardrail.StatusCode != http.StatusBadRequest {
		t.Errorf("removing a hand-written forbid returned %d, want 400",
			guardrail.StatusCode)
	}

	// And the composed one is.
	removed := requestWithCSRF(t, c, http.MethodDelete, "/api/policy/rules/"+ruleID, csrf)
	drain(removed)
	if removed.StatusCode != http.StatusOK {
		t.Fatalf("removing returned %d, want 200", removed.StatusCode)
	}
	for _, rule := range listRules(t, c) {
		if rule.ID == ruleID {
			t.Fatal("it was removed and is still in the live set")
		}
	}
}

type builtRule struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Composable bool     `json:"composable"`
	Summary    string   `json:"summary"`
	Missing    []string `json:"missing"`
}

func listRules(t *testing.T, c *http.Client) []builtRule {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/policy/rules", "application/json")
	defer drain(resp)

	var body struct {
		Rules []builtRule `json:"rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Rules
}
