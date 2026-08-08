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

// Consent, end to end.
//
// The property worth testing is not that a screen appears — it is that the
// screen cannot be skipped. A consent prompt enforced only in the SPA is
// advisory: anything driving the API directly, which is every attacker and most
// scripts, would never see it.

// TestConsentIsEnforcedServerSide.
//
// Resuming a parked authorization for a consent-requiring client must be
// refused until the user has actually agreed, regardless of what the UI did.
func TestConsentIsEnforcedServerSide(t *testing.T) {
	clientID := registerConsentClient(t)
	c := signedInClient(t)

	authID := parkAuthorization(t, c, clientID, "openid profile")

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/oidc/resume?auth="+url.QueryEscape(authID), "application/json")
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("resume returned %d for a client requiring consent, want 403: %s",
			resp.StatusCode, body)
	}
}

// TestConsentFlow walks the whole decision: asked, agreed, remembered,
// withdrawn, asked again.
//
// Written as one test rather than five because the interesting assertions are
// about the transitions between those states, and a shared client with a shared
// consent record is exactly what makes them observable.
func TestConsentFlow(t *testing.T) {
	clientID := registerConsentClient(t)
	c := signedInClient(t)
	csrf := csrfToken(t, c)

	// Start clean: an earlier run may have left agreement in place.
	revokeConsent(t, c, csrf, clientID)

	authID := parkAuthorization(t, c, clientID, "openid profile")

	pending := fetchPending(t, c, authID)
	if !pending.NeedsConsent {
		t.Fatal("a client registered with -consent must be asked about")
	}
	if pending.Application == "" || pending.Application == clientID {
		t.Errorf("application shown as %q — a consent screen naming an opaque "+
			"client id tells the user nothing about who is asking", pending.Application)
	}
	for _, scope := range pending.Scopes {
		if scope.Description == "" || scope.Description == scope.Scope {
			t.Errorf("scope %q has no description; a raw scope name is not "+
				"something a person can weigh", scope.Scope)
		}
	}

	// Agreeing completes the authorization.
	//nolint:bodyclose // postJSON closes the body before returning
	postJSON(t, c, "/api/oidc/consent", csrf,
		map[string]any{"auth": authID, "approve": true}, nil)

	resume := resumeAuthorization(t, c, authID)
	if resume == "" {
		t.Fatal("resume returned no continuation after consent was given")
	}

	// Asked once, not every time. A prompt on every sign-in becomes something
	// people dismiss unread, which records agreement nobody gave. With consent
	// on file the request must go straight to the provider's callback rather
	// than back to the UI.
	second := handoff(t, c, clientID, "openid profile")
	if strings.Contains(second, "oidc_auth") {
		t.Errorf("consent was requested a second time for the same scopes: %s", second)
	}
	if !strings.Contains(second, "/oidc/authorize/callback") {
		t.Errorf("expected the second authorization to complete silently, got %s", second)
	}

	// A wider request is a new decision.
	widerAuth := parkAuthorization(t, c, clientID, "openid profile email")
	if wider := fetchPending(t, c, widerAuth); !wider.NeedsConsent {
		t.Error("an application asking for more than was agreed must ask again")
	}

	// The agreement is visible where it can be withdrawn.
	consents := fetchConsents(t, c)
	found := false
	for _, consent := range consents {
		if consent.ClientID == clientID {
			found = true
		}
	}
	if !found {
		t.Fatalf("granted consent for %s does not appear in the connected "+
			"applications list, so the user cannot withdraw it", clientID)
	}

	// Withdrawal returns things to the start.
	revokeConsent(t, c, csrf, clientID)

	afterAuth := parkAuthorization(t, c, clientID, "openid profile")
	if after := fetchPending(t, c, afterAuth); !after.NeedsConsent {
		t.Error("consent was withdrawn but the application is still trusted")
	}
}

// TestRefusedConsentDiscardsTheRequest.
//
// Refusing must not leave the request parked. If it did, "no" would mean "not
// yet" and the application could collect the authorization on its next attempt.
func TestRefusedConsentDiscardsTheRequest(t *testing.T) {
	clientID := registerConsentClient(t)
	c := signedInClient(t)
	csrf := csrfToken(t, c)

	revokeConsent(t, c, csrf, clientID)
	authID := parkAuthorization(t, c, clientID, "openid profile")

	//nolint:bodyclose // postJSON closes the body before returning
	postJSON(t, c, "/api/oidc/consent", csrf,
		map[string]any{"auth": authID, "approve": false}, nil)

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/oidc/resume?auth="+url.QueryEscape(authID), "application/json")
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode < 400 {
		t.Fatalf("a refused authorization was still resumable (%d)", resp.StatusCode)
	}
}

type pendingAuthorization struct {
	Application string `json:"application"`
	ClientID    string `json:"clientId"`
	Scopes      []struct {
		Scope       string `json:"scope"`
		Description string `json:"description"`
	} `json:"scopes"`
	NeedsConsent bool `json:"needsConsent"`
}

func fetchPending(t *testing.T, c *http.Client, authID string) pendingAuthorization {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/oidc/pending?auth="+url.QueryEscape(authID), "application/json")
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("pending returned %d: %s", resp.StatusCode, body)
	}

	var pending pendingAuthorization
	if err := json.NewDecoder(resp.Body).Decode(&pending); err != nil {
		t.Fatal(err)
	}
	return pending
}

type grantedConsent struct {
	ClientID    string `json:"clientId"`
	Application string `json:"application"`
}

func fetchConsents(t *testing.T, c *http.Client) []grantedConsent {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/consents", "application/json")
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("listing consents returned %d: %s", resp.StatusCode, body)
	}

	var consents []grantedConsent
	if err := json.NewDecoder(resp.Body).Decode(&consents); err != nil {
		t.Fatal(err)
	}
	return consents
}

// revokeConsent withdraws agreement, tolerating there being none to withdraw so
// it doubles as a reset between runs.
func revokeConsent(t *testing.T, c *http.Client, csrf, clientID string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodDelete, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+"/api/consents/"+url.PathEscape(clientID), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Cardinal-CSRF", csrf)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("revoking consent returned %d: %s", resp.StatusCode, body)
	}
}

func resumeAuthorization(t *testing.T, c *http.Client, authID string) string {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/oidc/resume?auth="+url.QueryEscape(authID), "application/json")
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("resume returned %d: %s", resp.StatusCode, body)
	}

	var resume struct {
		Continue string `json:"continue"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&resume); err != nil {
		t.Fatal(err)
	}
	return resume.Continue
}

// signedInClient returns a client carrying a session, ready to drive the API.
func signedInClient(t *testing.T) *http.Client {
	t.Helper()

	c := client(t)
	cookie := establishSession(t)
	c.Jar.SetCookies(&url.URL{Scheme: "http", Host: hostCardinal},
		[]*http.Cookie{{Name: cookie.Name, Value: cookie.Value, Path: "/"}})
	return c
}

// pkceVerifier is fixed: these tests never exchange the code, so entropy buys
// nothing and a constant makes the challenge reproducible.
const pkceVerifier = "e2e-verifier-with-enough-entropy-to-be-valid-0123456789"

// parkAuthorization drives an authorization to the point where it waits for the
// user, and fails if it did not stop there.
func parkAuthorization(t *testing.T, c *http.Client, clientID, scope string) string {
	t.Helper()
	return parkedAuthorizationID(t, handoff(t, c, clientID, scope))
}

// handoff returns where /oidc/login sends the browser.
//
// Two outcomes are both correct and the difference is the thing under test:
// back to the UI carrying the request id when the user must do something, or
// straight to the provider's callback when nothing needs asking.
func handoff(t *testing.T, c *http.Client, clientID, scope string) string {
	t.Helper()

	q := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"scope":                 {scope},
		"redirect_uri":          {origin(hostRP) + "/callback"},
		"state":                 {"consent-test"},
		"nonce":                 {"consent-test-nonce"},
		"code_challenge":        {s256(pkceVerifier)},
		"code_challenge_method": {"S256"},
	}

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/oidc/authorize?"+q.Encode(), "text/html")
	resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read
	bridge := mustLocation(t, resp)

	resp = request(t, c, http.MethodGet, hostCardinal, pathOf(t, bridge), "text/html")
	resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	return mustLocation(t, resp)
}

// registerConsentClient creates a third-party-shaped client that must ask
// before it is given anything, reusing it across runs.
func registerConsentClient(t *testing.T) string {
	t.Helper()

	const name = "consent-required-client"

	if !strings.Contains(cardinalCLI(t, "app", "list"), name) {
		out, err := exec.CommandContext(t.Context(), "docker", "compose", "-f", "../../examples/compose.yml",
			"exec", "-T", "cardinal", "cardinal", "app", "register", name,
			"-redirect", origin(hostRP)+"/callback",
			"-dev-mode",
			"-consent",
			"-scopes", "openid,profile,email",
			"-config", "/etc/cardinal/cardinal.toml").CombinedOutput()
		if err != nil {
			t.Fatalf("registering consent client: %v\n%s", err, out)
		}
	}

	repointClient(t, name)

	out, err := exec.CommandContext(t.Context(), "docker", "compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "postgres", "psql", "-U", "cardinal", "-d", "cardinal", "-tAc",
		"SELECT client_id FROM oidc_clients c JOIN entities e ON e.id = c.entity_id "+
			"WHERE e.name = '"+name+"'").Output()
	if err != nil {
		t.Fatalf("reading client id: %v", err)
	}

	clientID := strings.TrimSpace(string(out))
	if clientID == "" {
		t.Fatal("consent client has no client_id")
	}
	return clientID
}
