package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
)

// TestUnregisteredScopeIsNotGranted.
//
// A client registered without `offline_access` must not receive a refresh
// token. Refresh tokens are long-lived, so granting one to a client that was
// never approved for it hands out a materially stronger credential than the
// registration says — and nobody reviewing the client list would see it.
//
// This is checked against a separate client registered with a narrow scope set,
// because the main relying party legitimately has offline_access and so cannot
// demonstrate the restriction.
func TestUnregisteredScopeIsNotGranted(t *testing.T) {
	clientID := registerNarrowClient(t)

	c := client(t)
	code, verifier := authorizeAs(t, c, clientID, "openid offline_access")

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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token exchange failed with %d: %s", resp.StatusCode, body)
	}

	var token struct {
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}

	if token.RefreshToken != "" {
		t.Error("a refresh token was issued to a client not registered for " +
			"offline_access — the client holds a longer-lived credential than " +
			"its registration shows")
	}
	if strings.Contains(token.Scope, "offline_access") {
		t.Errorf("granted scope %q includes offline_access, which this client "+
			"was not registered for", token.Scope)
	}
}

// registerNarrowClient creates a client with a deliberately restricted scope
// set, reusing it across runs so the test is idempotent.
func registerNarrowClient(t *testing.T) string {
	t.Helper()

	const name = "narrow-scope-client"

	if !strings.Contains(cardinalCLI(t, "app", "list"), name) {
		out, err := exec.Command("docker", "compose", "-f", "../../examples/compose.yml",
			"exec", "-T", "cardinal", "cardinal", "app", "register", name,
			"-redirect", origin(hostRP)+"/callback",
			"-dev-mode",
			// Deliberately no offline_access.
			"-scopes", "openid,profile",
			"-config", "/etc/cardinal/cardinal.toml").CombinedOutput()
		if err != nil {
			t.Fatalf("registering narrow client: %v\n%s", err, out)
		}
	}

	repointClient(t, name)

	out, err := exec.Command("docker", "compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "postgres", "psql", "-U", "cardinal", "-d", "cardinal", "-tAc",
		"SELECT client_id FROM oidc_clients c JOIN entities e ON e.id = c.entity_id "+
			"WHERE e.name = '"+name+"'").Output()
	if err != nil {
		t.Fatalf("reading client id: %v", err)
	}

	clientID := strings.TrimSpace(string(out))
	if clientID == "" {
		t.Fatal("narrow client has no client_id")
	}
	return clientID
}

// authorizeAs drives an authorization to the point of holding a code.
func authorizeAs(t *testing.T, c *http.Client, clientID, scope string) (code, verifier string) {
	t.Helper()

	verifier = "e2e-verifier-with-enough-entropy-to-be-valid-0123456789"
	challenge := s256(verifier)

	q := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"scope":                 {scope},
		"redirect_uri":          {origin(hostRP) + "/callback"},
		"state":                 {"scope-test"},
		"nonce":                 {"scope-test-nonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/oidc/authorize?"+q.Encode(), "text/html")
	resp.Body.Close()
	bridge := mustLocation(t, resp)

	resp = request(t, c, http.MethodGet, hostCardinal, pathOf(t, bridge), "text/html")
	resp.Body.Close()
	authID := parkedAuthorizationID(t, mustLocation(t, resp))

	cookie := establishSession(t)
	c.Jar.SetCookies(&url.URL{Scheme: "http", Host: hostCardinal},
		[]*http.Cookie{{Name: cookie.Name, Value: cookie.Value, Path: "/"}})

	resp = request(t, c, http.MethodGet, hostCardinal,
		"/api/oidc/resume?auth="+url.QueryEscape(authID), "application/json")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("resume failed with %d: %s", resp.StatusCode, body)
	}
	var resume struct {
		Continue string `json:"continue"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&resume); err != nil {
		t.Fatal(err)
	}

	callbackResp := request(t, c, http.MethodGet, hostCardinal, resume.Continue, "text/html")
	callbackResp.Body.Close()

	callback, err := url.Parse(mustLocation(t, callbackResp))
	if err != nil {
		t.Fatal(err)
	}
	code = callback.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", callback)
	}
	return code, verifier
}

// s256 computes the PKCE challenge for a verifier.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
