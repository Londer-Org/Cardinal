package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// OpenID Connect, driven through a relying party built on coreos/go-oidc.
//
// Every earlier OIDC check was curl against the endpoints, which proves they
// respond. This proves an independent client library is satisfied: discovery,
// JWKS fetch, signature verification, issuer and audience checks, and the nonce
// all have to hold, because go-oidc refuses the token otherwise.
//
// Using a different library from the provider's own is the point. zitadel's
// server satisfying zitadel's client would mostly show the two agree.

const hostRP = "client.localhost"

// TestRelyingPartyDiscoversTheProvider.
//
// If discovery had failed the client would not be serving at all, so reaching
// its home page is itself the assertion — go-oidc fetched
// /.well-known/openid-configuration and the JWKS at startup and accepted both.
func TestRelyingPartyDiscoversTheProvider(t *testing.T) {
	resp := request(t, client(t), http.MethodGet, hostRP, "/", "text/html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d — the relying party is not serving, which means go-oidc "+
			"rejected Cardinal's discovery document or JWKS", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Sign in with Cardinal") {
		t.Fatal("expected a signed-out home page")
	}
}

// TestAuthorizationRequestIsWellFormed checks what the client library decides
// to send, rather than what we would send by hand.
func TestAuthorizationRequestIsWellFormed(t *testing.T) {
	c := client(t)

	resp := request(t, c, http.MethodGet, hostRP, "/login", "text/html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want a redirect to the provider", resp.StatusCode)
	}

	target, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}

	if target.Host != "id.localhost:8100" || target.Path != "/oidc/authorize" {
		t.Fatalf("redirected to %s, want the issuer's authorize endpoint", target)
	}

	q := target.Query()
	for _, check := range []struct{ param, want, why string }{
		{"response_type", "code", "only the code flow is offered; implicit puts tokens in the URL fragment"},
		{"code_challenge_method", "S256", "plain would let anyone who intercepted the challenge derive the verifier"},
	} {
		if got := q.Get(check.param); got != check.want {
			t.Errorf("%s = %q, want %q — %s", check.param, got, check.want, check.why)
		}
	}
	for _, param := range []string{"state", "nonce", "code_challenge", "client_id"} {
		if q.Get(param) == "" {
			t.Errorf("%s is missing from the authorization request", param)
		}
	}
	if !strings.Contains(q.Get("scope"), "offline_access") {
		t.Error("offline_access not requested, so no refresh token will be issued")
	}
}

// TestFullOIDCLogin is the end-to-end path: an application sends an
// unauthenticated user to Cardinal, they sign in, and the application ends up
// holding a token it has independently verified.
func TestFullOIDCLogin(t *testing.T) {
	c := client(t)
	completeOIDCLogin(t, c)

	resp := request(t, c, http.MethodGet, hostRP, "/whoami.json", "application/json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d after sign-in: %s", resp.StatusCode, body)
	}

	var result struct {
		Subject string         `json:"sub"`
		Claims  map[string]any `json:"claims"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	if result.Subject == "" {
		t.Fatal("no subject — the ID token had no `sub` claim")
	}

	// The claims go-oidc accepted. Their presence means the signature verified
	// against the JWKS and the issuer and audience matched.
	for _, claim := range []string{"iss", "aud", "sub", "exp", "iat", "nonce"} {
		if _, ok := result.Claims[claim]; !ok {
			t.Errorf("claim %q missing from the verified ID token", claim)
		}
	}

	// amr must report how the subject actually authenticated, so a relying
	// party can refuse an emergency session for a sensitive operation rather
	// than trusting that Cardinal's policy matched its needs.
	amr, ok := result.Claims["amr"].([]any)
	if !ok || len(amr) == 0 {
		t.Fatalf("amr missing or empty: %v", result.Claims["amr"])
	}
	if !slices.Contains(amr, any("hwk")) {
		t.Errorf("amr = %v, want hwk for a device-bound passkey session — a "+
			"relying party uses this to make its own step-up decision rather "+
			"than trusting that Cardinal's policy matched its needs", amr)
	}
}

// TestRefreshTokenRotation.
//
// Cardinal revokes the old refresh token as it issues a new one. That is
// required by OAuth 2.1 for public clients and worth doing for all of them: a
// stolen refresh token is long-lived, so rotation both limits the window and
// makes theft detectable, because the legitimate client's next refresh fails
// rather than silently succeeding alongside the thief's.
//
// This path had never actually run before this test existed.
func TestRefreshTokenRotation(t *testing.T) {
	c := client(t)
	completeOIDCLogin(t, c)

	resp := request(t, c, http.MethodPost, hostRP, "/refresh", "application/json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("refresh failed with %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Refreshed      int  `json:"refreshed"`
		Rotated        bool `json:"rotated"`
		NewAccessToken bool `json:"newAccessToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	if !result.NewAccessToken {
		t.Error("no new access token was issued")
	}
	if !result.Rotated {
		t.Error("the refresh token was not rotated — a stolen one would stay " +
			"valid indefinitely, and theft would be undetectable")
	}

	t.Run("rotation survives a second round", func(t *testing.T) {
		// The second refresh uses the token issued by the first. If rotation
		// revoked the wrong token, this is where it shows.
		resp := request(t, c, http.MethodPost, hostRP, "/refresh", "application/json")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("second refresh failed with %d: %s — rotation revoked the "+
				"token it had just issued", resp.StatusCode, body)
		}
	})
}

// completeOIDCLogin drives a browser-shaped login: relying party → Cardinal →
// sign in → back to the relying party with a verified token.
func completeOIDCLogin(t *testing.T, c *http.Client) {
	t.Helper()

	// 1. The application sends the user to the provider.
	resp := request(t, c, http.MethodGet, hostRP, "/login", "text/html")
	resp.Body.Close()
	authorize := mustLocation(t, resp)

	// 2. The provider parks the request and hands off to Cardinal's login
	//    bridge.
	resp = request(t, c, http.MethodGet, hostCardinal, pathOf(t, authorize), "text/html")
	resp.Body.Close()
	bridge := mustLocation(t, resp)

	// 3. With no session, the bridge sends the browser to the SPA, carrying the
	//    authorization id so it can be resumed after sign-in.
	resp = request(t, c, http.MethodGet, hostCardinal, pathOf(t, bridge), "text/html")
	resp.Body.Close()
	authID := parkedAuthorizationID(t, mustLocation(t, resp))

	// 4. Sign in. Break-glass stands in for a passkey, which needs a human.
	cookie := establishSession(t)
	for _, host := range []string{hostCardinal, hostRP} {
		c.Jar.SetCookies(&url.URL{Scheme: "http", Host: host},
			[]*http.Cookie{{Name: cookie.Name, Value: cookie.Value, Path: "/"}})
	}

	// 5. The SPA completes the parked authorization.
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

	// 6. Back to the provider, which mints the code and redirects to the app.
	resp = request(t, c, http.MethodGet, hostCardinal, resume.Continue, "text/html")
	resp.Body.Close()
	callback := mustLocation(t, resp)

	// 7. The relying party exchanges the code and verifies the ID token. A
	//    redirect here means it succeeded; anything else means go-oidc refused.
	resp = request(t, c, http.MethodGet, hostRP, pathOf(t, callback), "text/html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("the relying party rejected the token (%d): %s", resp.StatusCode, body)
	}
}

func mustLocation(t *testing.T, resp *http.Response) string {
	t.Helper()
	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatalf("expected a redirect, got %d with no Location", resp.StatusCode)
	}
	return location
}

// pathOf reduces an absolute URL to path plus query, since requests are dialled
// at the gateway with the host supplied separately.
func pathOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.RawQuery == "" {
		return u.Path
	}
	return u.Path + "?" + u.RawQuery
}

func parkedAuthorizationID(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	id := u.Query().Get("oidc_auth")
	if id == "" {
		t.Fatalf("no oidc_auth in %q — the provider did not park the request "+
			"where the SPA can resume it", raw)
	}
	return id
}
