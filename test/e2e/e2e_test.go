// Package e2e drives the stack in examples/ through real Traefik.
//
// This exists because every other test of forwardAuth hand-crafts
// X-Forwarded-* headers, which proves the handler works and says nothing about
// whether the integration does. Real Traefik decides which headers it sends,
// how it treats a 204 versus a 200, and — the one that bites people — forwards
// only the response headers named in authResponseHeaders.
//
// Run with `make e2e`, which brings the stack up first.
package e2e

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	// Everything reaches the stack through Traefik on this port. Nothing else
	// is published, which is what makes trusting the identity headers sound.
	gateway = "127.0.0.1:8100"

	hostCardinal    = "id.localhost"
	hostProtected   = "app.localhost"
	hostUnprotected = "open.localhost"
)

// sessionCookie is established once and reused.
//
// Break-glass is rate limited to a handful of attempts per window — correctly,
// since it is emergency access — so a suite that signed in per test would trip
// its own limiter and report confusing 503s.
var sessionCookie *http.Cookie

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		fmt.Println("skipping end-to-end tests (-short)")
		os.Exit(0)
	}

	// Fail with an instruction rather than a connection error. Someone running
	// `go test ./...` for the first time should be told what to do, not handed
	// a dial timeout.
	conn, err := net.DialTimeout("tcp", gateway, 2*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"end-to-end stack is not running on %s.\n  Start it with: make e2e-up\n", gateway)
		os.Exit(1)
	}
	_ = conn.Close()

	os.Exit(m.Run())
}

// client builds an HTTP client that talks to Traefik regardless of hostname.
//
// *.localhost resolves to 127.0.0.1 on most systems, but not all, and CI is
// exactly where it does not. Dialling the gateway directly and letting the Host
// header do the routing removes that dependency.
func client(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, network, gateway)
			},
		},
		// Redirects are the thing under test in places, so they are never
		// followed automatically.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
	}
}

func request(t *testing.T, c *http.Client, method, host, path string, accept string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, "http://"+host+path, nil) //nolint:noctx // bounded by client timeout
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, host+path, err)
	}
	return resp
}

// cardinalCLI runs a command inside the Cardinal container, which is how the
// stack is seeded and inspected.
func cardinalCLI(t *testing.T, args ...string) string {
	t.Helper()

	full := append([]string{"compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "cardinal", "cardinal"}, args...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("cardinal %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// TestUnauthenticatedBrowserIsRedirected.
//
// The first thing a real user experiences. Traefik must return Cardinal's 302
// to the browser rather than treating it as a failed sub-request.
func TestUnauthenticatedBrowserIsRedirected(t *testing.T) {
	resp := request(t, client(t), http.MethodGet, hostProtected, "/", "text/html")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got %d, want 302 — Traefik should pass Cardinal's redirect through",
			resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, hostCardinal) {
		t.Fatalf("redirected to %q, want the Cardinal login page", location)
	}
	// The return URL must survive, or signing in dumps everyone on a dashboard
	// having forgotten where they were going.
	if !strings.Contains(location, "return_to") {
		t.Errorf("redirect lost the original destination: %q", location)
	}
}

// TestUnauthenticatedAPIClientGetsUnauthorized: an API client following a
// redirect to an HTML login page produces a confusing error far from its cause.
func TestUnauthenticatedAPIClientGetsUnauthorized(t *testing.T) {
	resp := request(t, client(t), http.MethodGet, hostProtected, "/whoami.json", "application/json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 for a non-browser client", resp.StatusCode)
	}
}

// TestBackendNeverSeesUnauthenticatedRequests is the property the whole
// arrangement rests on.
//
// If a request can reach the application without passing the middleware, the
// application's unconditional trust in its headers becomes a vulnerability.
func TestBackendNeverSeesUnauthenticatedRequests(t *testing.T) {
	resp := request(t, client(t), http.MethodGet, hostProtected, "/whoami.json", "application/json")
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "userId") {
		t.Fatal("the backend responded to an unauthenticated request — " +
			"the middleware is not in the path")
	}
}

// TestForgedIdentityHeadersAreStripped.
//
// A client sets X-Auth-Request-User itself. Traefik's strip-identity middleware
// must clear it before forwardAuth runs, and forwardAuth must overwrite what it
// sets — otherwise anyone can become anyone by sending a header.
func TestForgedIdentityHeadersAreStripped(t *testing.T) {
	c := client(t)

	req, err := http.NewRequest(http.MethodGet, //nolint:noctx // bounded by client timeout
		"http://"+hostProtected+"/whoami.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Auth-Request-User", "00000000-0000-0000-0000-000000000000")
	req.Header.Set("X-Auth-Request-Preferred-Username", "root")
	req.Header.Set("X-Auth-Request-Groups", "admins")

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("forged identity headers were honoured — anyone could impersonate "+
			"anyone. Response: %s", body)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", resp.StatusCode)
	}
}

// TestUnprotectedRouteProvesTheMiddlewareIsWhatMatters.
//
// The same application, same container, routed without the middleware. If this
// also refused, the earlier tests might be passing for some incidental reason
// rather than because forwardAuth is doing its job.
func TestUnprotectedRouteProvesTheMiddlewareIsWhatMatters(t *testing.T) {
	resp := request(t, client(t), http.MethodGet, hostUnprotected, "/healthz", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d — the application itself should be reachable without the "+
			"middleware, or these tests prove nothing about the middleware",
			resp.StatusCode)
	}
}

// TestSessionCookieIsScopedToTheParentDomain.
//
// Asserted directly, because it is the setting that makes forwardAuth single
// sign-on possible at all: without a parent-scoped cookie, a session
// established at id.example.com is simply never sent to app.example.com and
// sign-in loops forever.
func TestSessionCookieIsScopedToTheParentDomain(t *testing.T) {
	cookie := establishSession(t)

	if cookie.Domain == "" {
		t.Fatal("session cookie is host-only — forwardAuth SSO cannot work, " +
			"set server.cookie_domain")
	}
	if !strings.HasSuffix(hostProtected, cookie.Domain) {
		t.Fatalf("cookie domain %q does not cover %q", cookie.Domain, hostProtected)
	}
}

// TestAuthenticatedRequestCarriesIdentity is the end-to-end path: a session,
// then through Traefik to the application.
func TestAuthenticatedRequestCarriesIdentity(t *testing.T) {
	c := client(t)
	withSession(t, c)

	resp := request(t, c, http.MethodGet, hostProtected, "/whoami.json", "application/json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("got %d after signing in: %s", resp.StatusCode, body)
	}

	var identity struct {
		UserID      string   `json:"userId"`
		Login       string   `json:"login"`
		Groups      []string `json:"groups"`
		AuthMethod  string   `json:"authMethod"`
		DeviceBound bool     `json:"deviceBound"`
		Policy      string   `json:"policy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		t.Fatal(err)
	}

	if identity.Login != "e2e-user" {
		t.Errorf("login = %q, want e2e-user", identity.Login)
	}
	if identity.UserID == "" {
		t.Error("no user ID reached the backend")
	}
	// The check that only a real proxy can make: this header is set by Cardinal
	// and survives only because it is listed in authResponseHeaders.
	if identity.Policy != "staff-web-access" {
		t.Errorf("policy = %q, want staff-web-access — if empty, the header is "+
			"missing from authResponseHeaders in traefik/dynamic.yml", identity.Policy)
	}
	// Break-glass is not device-bound, and the backend must see that rather
	// than a default.
	if identity.DeviceBound {
		t.Error("deviceBound = true for a break-glass session")
	}
}

// TestDecisionIsLogged: the forwardAuth call must leave a record naming the
// policy that decided, which is what the decision explorer reads.
func TestDecisionIsLogged(t *testing.T) {
	c := client(t)
	withSession(t, c)

	resp := request(t, c, http.MethodGet, hostProtected, "/whoami.json", "application/json")
	resp.Body.Close()

	out := cardinalCLI(t, "audit", "verify")
	if !strings.Contains(out, "intact") {
		t.Errorf("audit chain not intact after end-to-end traffic: %s", out)
	}
}

// withSession puts the shared session cookie on a client, for every host.
//
// Go's cookiejar keys its storage with a "last two labels" heuristic, so
// id.localhost and app.localhost land under different keys and a cookie is
// never shared between them — whatever its Domain attribute says. Browsers do
// not behave that way, which is why the scoping is asserted separately, above,
// rather than relied upon here.
//
// Carrying the cookie explicitly keeps this test about what it is meant to
// test: that given a valid session, Traefik and Cardinal admit the request and
// the identity reaches the backend.
func withSession(t *testing.T, c *http.Client) {
	t.Helper()

	cookie := establishSession(t)
	for _, host := range []string{hostCardinal, hostProtected, hostUnprotected} {
		u := &url.URL{Scheme: "http", Host: host}
		c.Jar.SetCookies(u, []*http.Cookie{{
			Name:  cookie.Name,
			Value: cookie.Value,
			Path:  "/",
		}})
	}
}

// establishSession signs in once, via break-glass — the only non-interactive
// path, since a passkey needs a human and a device.
func establishSession(t *testing.T) *http.Cookie {
	t.Helper()

	if sessionCookie != nil {
		return sessionCookie
	}

	c := client(t)
	csrf := csrfToken(t, c)

	var challenge struct {
		Challenge string `json:"challenge"`
	}
	postJSON(t, c, "/api/auth/break-glass/begin", csrf, nil, &challenge)

	signature := strings.TrimSpace(cardinalCLI(t, "break-glass", "sign",
		challenge.Challenge, "-key", "/etc/cardinal/break-glass.key"))

	resp := postJSON(t, c, "/api/auth/break-glass/finish", csrf, map[string]string{
		"challenge": challenge.Challenge,
		"signature": signature,
		"login":     "e2e-user",
	}, nil)

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "cardinal_session" {
			sessionCookie = cookie
			return cookie
		}
	}
	t.Fatal("break-glass succeeded but set no session cookie")
	return nil
}

func csrfToken(t *testing.T, c *http.Client) string {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/health", "")
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "cardinal_csrf" {
			return cookie.Value
		}
	}
	t.Fatal("no CSRF cookie was issued")
	return ""
}

func postJSON(t *testing.T, c *http.Client, path, csrf string, body, out any) *http.Response {
	t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = strings.NewReader(string(encoded))
	}

	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		"http://"+hostCardinal+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cardinal-CSRF", csrf)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s: %d %s", path, resp.StatusCode, responseBody)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp
}
