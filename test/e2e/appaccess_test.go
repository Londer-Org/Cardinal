package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Who may sign in to which application.
//
// The shipped policy permits everyone, so the interesting case is a narrowed
// one — and the property worth proving is that narrowing it cannot be stepped
// around by driving the API directly, which is what anything other than the SPA
// does.

// TestApplicationAccessIsEnforcedServerSide.
//
// Publishes a policy that names one application and permits nobody for it, then
// checks every path that can complete an authorization refuses.
func TestApplicationAccessIsEnforcedServerSide(t *testing.T) {
	clientID := registerConsentClient(t)
	restore := publishPolicy(t, denyConsentClientPolicy)
	defer restore()

	c := signedInClient(t)

	// Taken from the provider's own hand-off rather than by following it,
	// because following it is now refused — which is the point, and which makes
	// parkAuthorization unusable here.
	authID := authorizationID(t, c, clientID, "openid profile")

	t.Run("the SPA is told before it tries", func(t *testing.T) {
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/oidc/pending?auth="+url.QueryEscape(authID), "application/json")
		defer drain(resp)

		var pending struct {
			Denied       bool     `json:"denied"`
			DeniedReason string   `json:"deniedReason"`
			DeniedBy     []string `json:"deniedBy"`
			Application  string   `json:"application"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
			t.Fatal(err)
		}
		if !pending.Denied {
			t.Fatal("policy refuses this application, but pending reported access")
		}
		if !strings.Contains(pending.DeniedReason, pending.Application) {
			t.Errorf("refusal %q does not name the application, so the user cannot "+
				"tell whether they are locked out of one thing or everything",
				pending.DeniedReason)
		}
	})

	t.Run("resuming directly is refused", func(t *testing.T) {
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/oidc/resume?auth="+url.QueryEscape(authID), "application/json")
		defer drain(resp)

		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("resume returned %d for a refused application, want 403: %s — "+
				"a check only the SPA performs is a check anything else skips",
				resp.StatusCode, body)
		}
	})

	t.Run("the single-sign-on hand-off is refused", func(t *testing.T) {
		// The path an already-signed-in user takes, which completes without the
		// SPA ever being involved.
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/oidc/login?auth="+url.QueryEscape(authID), "text/html")
		defer drain(resp)

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("the SSO hand-off returned %d for a refused application, want 403",
				resp.StatusCode)
		}
	})

	t.Run("the decision is logged and names the rule", func(t *testing.T) {
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/decisions?limit=100&denied=true", "application/json")
		defer drain(resp)

		var records []struct {
			DecisionPoint string `json:"decisionPoint"`
			Action        string `json:"action"`
			Allowed       bool   `json:"allowed"`
			Explanation   string `json:"explanation"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if record.DecisionPoint == "oidcAuthorize" &&
				record.Action == "AccessApplication" && !record.Allowed {
				if record.Explanation == "" {
					t.Error("the decision carries no explanation, so the explorer " +
						"has nothing to show")
				}
				return
			}
		}
		t.Fatal("the refusal was not logged as a decision")
	})
}

// TestOtherApplicationsAreUnaffected.
//
// A rule naming one application must not quietly govern the rest — the failure
// mode that turns a narrowing into an outage.
func TestOtherApplicationsAreUnaffected(t *testing.T) {
	restore := publishPolicy(t, denyConsentClientPolicy)
	defer restore()

	c := client(t)
	completeOIDCLogin(t, c)
}

// denyConsentClientPolicy permits every application except one.
//
// Written as a forbid rather than by omitting a permit, because the shipped set
// permits everything and this has to override it — which is also the shape an
// operator reaches for first.
const denyConsentClientPolicy = `
@id("any-user-may-access-any-application")
permit (
    principal,
    action == Cardinal::Action::"AccessApplication",
    resource
);

@id("nobody-may-access-the-consent-client")
forbid (
    principal,
    action == Cardinal::Action::"AccessApplication",
    resource == Cardinal::Application::"consent-required-client"
);

@id("staff-web-access")
permit (
    principal,
    action == Cardinal::Action::"AccessURL",
    resource
)
when {
    context has audience && context.audience == "staff"
};

@id("directory-admins-may-administer")
permit (
    principal in Cardinal::Group::"00000000-0000-7000-8000-00000000ad11",
    action == Cardinal::Action::"AdministerDirectory",
    resource
);

@id("admin-requires-fresh-device-bound-auth")
forbid (
    principal,
    action == Cardinal::Action::"AdministerDirectory",
    resource
)
unless {
    principal.deviceBound && principal.authAgeSeconds <= 300
};
`

// publishPolicy activates a policy set and returns a function restoring the
// shipped one.
//
// The server loads policy at startup, so both directions restart it. That makes
// these tests slow and unshareable with parallel ones — which is the honest
// cost of testing the real loading path rather than a fixture the deployment
// never uses.
func publishPolicy(t *testing.T, document string) func() {
	t.Helper()

	apply := func(path string) {
		//nolint:gosec // paths are written in this file, not taken from input
		out, err := exec.CommandContext(t.Context(), "docker", "compose",
			"-f", "../../examples/compose.yml", "exec", "-T", "cardinal",
			"cardinal", "policy", "publish", path,
			"-description", "e2e application access", "-activate").CombinedOutput()
		if err != nil {
			t.Fatalf("publishing policy: %v\n%s", err, out)
		}

		if out, err := exec.CommandContext(t.Context(), "docker", "compose",
			"-f", "../../examples/compose.yml", "restart", "cardinal").CombinedOutput(); err != nil {
			t.Fatalf("restarting: %v\n%s", err, out)
		}
		waitForCardinal(t)
	}

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

	// World-readable before copying: the container runs as nonroot, and docker
	// cp preserves the mode, so a 0600 temp file lands unreadable inside. It is
	// a test policy in a temp dir, not a secret.
	//nolint:gosec // deliberately readable; see above
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		t.Fatal(err)
	}

	//nolint:gosec // path from t.TempDir
	if out, err := exec.CommandContext(t.Context(), "docker", "cp", tmp.Name(),
		containerID(t)+":/tmp/e2e-policy.cedar").CombinedOutput(); err != nil {
		t.Fatalf("copying policy: %v\n%s", err, out)
	}
	apply("/tmp/e2e-policy.cedar")

	return func() {
		//nolint:gosec // fixed path
		if out, err := exec.CommandContext(context.WithoutCancel(t.Context()), "docker", "cp",
			"../../policies/cardinal.cedar",
			containerID(t)+":/tmp/cardinal.cedar").CombinedOutput(); err != nil {
			t.Fatalf("restoring policy: %v\n%s", err, out)
		}
		apply("/tmp/cardinal.cedar")
	}
}

func containerID(t *testing.T) string {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "docker", "compose",
		"-f", "../../examples/compose.yml", "ps", "-q", "cardinal").Output()
	if err != nil {
		t.Fatalf("finding the cardinal container: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func waitForCardinal(t *testing.T) {
	t.Helper()

	c := client(t)
	for range 60 {
		//nolint:noctx // bounded by the client timeout
		resp, err := c.Get("http://" + hostCardinal + "/api/health")
		if err == nil {
			drain(resp)
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("cardinal did not come back after a restart")
}

// authorizationID starts an authorization and returns its id.
//
// Stops at the provider's redirect to /oidc/login rather than following it. The
// request is parked by then — the id is in that redirect — and following it is
// exactly what this test expects to be refused.
func authorizationID(t *testing.T, c *http.Client, clientID, scope string) string {
	t.Helper()

	q := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"scope":                 {scope},
		"redirect_uri":          {"http://client.localhost:8100/callback"},
		"state":                 {"access-test"},
		"nonce":                 {"access-test-nonce"},
		"code_challenge":        {s256(pkceVerifier)},
		"code_challenge_method": {"S256"},
	}

	//nolint:bodyclose // drain closes it
	resp := request(t, c, http.MethodGet, hostCardinal,
		"/oidc/authorize?"+q.Encode(), "text/html")
	drain(resp)

	bridge, err := url.Parse(mustLocation(t, resp))
	if err != nil {
		t.Fatal(err)
	}
	id := bridge.Query().Get("auth")
	if id == "" {
		t.Fatalf("no auth id in %q — the provider did not park the request", bridge)
	}
	return id
}
