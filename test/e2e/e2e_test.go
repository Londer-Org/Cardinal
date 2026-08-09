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
	hostCardinal    = "id.cardinal.test"
	hostProtected   = "app.cardinal.test"
	hostUnprotected = "open.cardinal.test"
)

// port is where the example stack is published.
//
// Read from the environment with the same default the Makefile uses, so a
// machine that already has something on 8443 can move the whole stack with
// CARDINAL_PORT and have the suite follow. Hardcoding it meant the suite could
// silently dial whatever else held the port — which is not hypothetical, and is
// the sort of failure that looks like Cardinal being broken.
func port() string {
	if p := os.Getenv("CARDINAL_PORT"); p != "" {
		return p
	}
	return "8443"
}

// gateway is the address everything dials. Nothing else is published, which is
// what makes trusting the identity headers sound.
func gateway() string { return "127.0.0.1:" + port() }

// origin is where a hostname actually lives.
//
// HTTPS, and not as a formality. The stack cannot be served over plain HTTP and
// still work in a browser: WebAuthn needs a secure context, forwardAuth SSO
// needs a parent-domain cookie, and no http origin gives both. Testing against
// http would be testing an arrangement that cannot exist.
func origin(host string) string { return "https://" + host + ":" + port() }

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
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(context.Background(), "tcp", gateway())
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"end-to-end stack is not running on %s.\n  Start it with: make e2e-up\n", gateway())
		os.Exit(1)
	}
	_ = conn.Close() //nolint:errcheck // best effort; the meaningful error is the one being returned

	// And separately: the stack can be up while its certificate is not trusted,
	// which produces a handshake failure in every test and looks like the whole
	// suite breaking at once. Said here, once, with the fix.
	if _, err := client(&testing.T{}).Get(origin(hostCardinal) + "/api/health"); err != nil { //nolint:noctx,bodyclose // one probe, message is the point
		fmt.Fprintf(os.Stderr,
			"the stack is listening but %s did not verify:\n  %v\n\n"+
				"  The certificate comes from the local CA mkcert installed.\n"+
				"  Check `make e2e-check`, then `mkcert -install`.\n",
			origin(hostCardinal), err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// client builds an HTTP client that talks to Traefik regardless of hostname.
//
// The names are in /etc/hosts on a developer machine and nowhere in CI.
// Dialling the gateway directly and letting SNI and the Host header do the
// routing removes that dependency.
//
// TLS is verified rather than skipped, deliberately. The certificate comes from
// the local CA mkcert installed, and checking it here means this suite fails
// the same way a browser would if that setup is missing or has expired —
// InsecureSkipVerify would hide exactly the class of problem that made this
// stack unusable in a browser for months.
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
				return dialer.DialContext(ctx, network, gateway())
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

	req, err := http.NewRequest(method, origin(host)+path, nil) //nolint:noctx // bounded by client timeout
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

	full := append([]string{
		"compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "cardinal", "cardinal",
	}, args...)
	out, err := exec.CommandContext(t.Context(), "docker", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("cardinal %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// tryCardinalCLI is cardinalCLI for commands that may legitimately fail.
//
// The stack outlives a single `go test` run, so seeding something that already
// exists is normal rather than a problem. Distinguishing "already there" from a
// real failure by parsing an error message would be worse than tolerating both:
// whatever the command was meant to establish is asserted by the test itself a
// few lines later.
func tryCardinalCLI(t *testing.T, args ...string) {
	t.Helper()

	full := append([]string{
		"compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "cardinal", "cardinal",
	}, args...)
	_, _ = exec.CommandContext(t.Context(), "docker", full...).CombinedOutput() //nolint:errcheck // best-effort teardown; the test has already reported its result
}

// repointClient makes a registered client's redirect URI match the current port.
//
// A registration embeds the port and the stack outlives a run, so a client left
// over from a run on a different CARDINAL_PORT points at the old one — and
// every authorization then fails with a redirect-URI mismatch, correctly, and
// looking nothing like a stale fixture. The registering helpers all tolerate
// "already exists" by design, which is what lets the stale row survive.
//
// Direct SQL because this is fixture maintenance, not a product operation:
// there is no "change a client's redirect URI" command, and adding one to make
// a test tidy would be the tail wagging the dog.
func repointClient(t *testing.T, name string) {
	t.Helper()

	seedSQL(t, `UPDATE oidc_clients
	               SET redirect_uris = ARRAY['`+origin(hostRP)+`/callback']
	             WHERE entity_id = (SELECT id FROM entities
	                                 WHERE type = 'application' AND name = '`+name+`')`)
}

// TestUnauthenticatedBrowserIsRedirected.
//
// The first thing a real user experiences. Traefik must return Cardinal's 302
// to the browser rather than treating it as a failed sub-request.
func TestUnauthenticatedBrowserIsRedirected(t *testing.T) {
	resp := request(t, client(t), http.MethodGet, hostProtected, "/", "text/html")
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

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
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

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
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
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
		origin(hostProtected)+"/whoami.json", nil)
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
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
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
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

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
	// Asserted on the CSRF cookie rather than the session cookie, because the
	// suite now seeds its session directly and so never sees a Set-Cookie for
	// it. Both are issued with the same Domain from the same setting, so this
	// still fails if cookie_domain is wrong — which is the thing worth
	// catching.
	c := client(t)
	resp := request(t, c, http.MethodGet, hostCardinal, "/api/health", "") //nolint:bodyclose // the helper drains and closes it; bodyclose cannot see through the call
	defer drain(resp)

	var domain string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "cardinal_csrf" {
			domain = cookie.Domain
		}
	}

	// This says the server *sent* the right Domain. It does not say a browser
	// kept it, and against the shipped example a browser does not: Chrome
	// discards any cookie whose Domain attribute is a public suffix, and
	// `localhost` is one. So this passes while, in Chrome, no session cookie is
	// stored and every mutation from the console returns 403.
	//
	// net/http/cookiejar accepts Domain=localhost, which is why an entire
	// browser-less suite agrees with itself here. Nothing in Go can catch it —
	// the check has to be a real browser, and it lives in tools/uishot.
	//
	// Not fixable by changing this setting either. Every parent of a *.localhost
	// name is `localhost`, so with these hostnames a parent-domain cookie is
	// impossible in a browser and host-only breaks the forwardAuth demo this
	// test exists to protect. The example needs different hostnames.
	if domain == "" {
		t.Fatal("cookies are host-only — forwardAuth SSO cannot work, " +
			"set server.cookie_domain")
	}
	if !strings.HasSuffix(hostProtected, domain) {
		t.Fatalf("cookie domain %q does not cover %q", domain, hostProtected)
	}
}

// TestAuthenticatedRequestCarriesIdentity is the end-to-end path: a session,
// then through Traefik to the application.
func TestAuthenticatedRequestCarriesIdentity(t *testing.T) {
	c := client(t)
	withSession(t, c)

	resp := request(t, c, http.MethodGet, hostProtected, "/whoami.json", "application/json")
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
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
	// The seeded session is device-bound, and the backend must see that rather
	// than a default — this header is what lets an application make its own
	// step-up decision without asking Cardinal again.
	if !identity.DeviceBound {
		t.Error("deviceBound = false for a device-bound session; the backend " +
			"cannot make its own step-up decisions if this is wrong")
	}
}

// TestDecisionIsLogged: the forwardAuth call must leave a record naming the
// policy that decided, which is what the decision explorer reads.
func TestDecisionIsLogged(t *testing.T) {
	c := client(t)
	withSession(t, c)

	resp := request(t, c, http.MethodGet, hostProtected, "/whoami.json", "application/json")
	resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	out := cardinalCLI(t, "audit", "verify")
	if !strings.Contains(out, "intact") {
		t.Errorf("audit chain not intact after end-to-end traffic: %s", out)
	}
}

// withSession puts the shared session cookie on a client, for every host.
//
// Go's cookiejar keys its storage with a "last two labels" heuristic, so
// id.cardinal.test and app.cardinal.test land under different keys and a cookie is
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

// establishSession seeds a signed-in session directly in the database.
//
// The only credential Cardinal accepts is a passkey, and tapping one needs a
// human with a key — so a headless suite has to start from a session rather
// than earn one. What is inserted is exactly what a passkey sign-in produces,
// so everything downstream of authentication is genuinely exercised.
//
// This used to sign in with break-glass, which was the only non-interactive
// path. Removing break-glass (ADR 0014) took that away, and seeding is the
// honest replacement: it skips the same ceremony, without a production
// mechanism existing solely to make tests convenient.
func establishSession(t *testing.T) *http.Cookie {
	t.Helper()

	if sessionCookie != nil {
		return sessionCookie
	}

	const token = "e2e-session-token-with-plenty-of-entropy-0123456789abcdef"

	seedSQL(t, `DELETE FROM sessions WHERE token_hash = sha256('`+token+`'::bytea)`)
	seedSQL(t, `INSERT INTO sessions
	              (subject_id, token_hash, valid_period, auth_method, auth_at,
	               device_bound, absolute_expiry)
	            SELECT e.id, sha256('`+token+`'::bytea),
	                   tstzrange(now(), now() + interval '1 hour'), 'passkey', now(),
	                   true, now() + interval '7 days'
	              FROM entities e WHERE e.name = 'e2e-user'`)

	sessionCookie = &http.Cookie{Name: "cardinal_session", Value: token, Path: "/"}
	return sessionCookie
}

// seedQuery runs a scalar query against the stack's database.
func seedQuery(t *testing.T, query string) string {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "docker", "compose",
		"-f", "../../examples/compose.yml",
		"exec", "-T", "postgres", "psql", "-U", "cardinal", "-d", "cardinal",
		"-tAc", query).Output()
	if err != nil {
		t.Fatalf("querying: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// seedSQL runs a statement against the stack's database.
func seedSQL(t *testing.T, statement string) {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "docker", "compose",
		"-f", "../../examples/compose.yml",
		"exec", "-T", "postgres", "psql", "-U", "cardinal", "-d", "cardinal",
		"-v", "ON_ERROR_STOP=1", "-c", statement).CombinedOutput()
	if err != nil {
		t.Fatalf("seeding: %v\n%s", err, out)
	}
}

func csrfToken(t *testing.T, c *http.Client) string {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/health", "")
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

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
		origin(hostCardinal)+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cardinal-CSRF", csrf)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
		t.Fatalf("POST %s: %d %s", path, resp.StatusCode, responseBody)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	return resp
}

// TestHealthSaysWhichBuildAndWhichPolicy.
//
// Both are the questions asked of a node during a rolling deploy that went
// wrong, and both are otherwise answerable only by getting a shell on it —
// which is exactly what you cannot do at that moment.
//
// The policy version matters separately from the build. Policy is loaded
// asynchronously: serve.go polls for an activated version every ten seconds, so
// a node can be enforcing a set the database no longer calls active, and nothing
// outside the process could see that. Found the hard way, by a script that
// waited for a new policy by grepping the log for a line every earlier startup
// had also written.
func TestHealthSaysWhichBuildAndWhichPolicy(t *testing.T) {
	var body struct {
		Status        string `json:"status"`
		Version       string `json:"version"`
		PolicyVersion *int64 `json:"policyVersion"`
	}

	resp := request(t, client(t), http.MethodGet, hostCardinal, "/api/health", "")
	defer drain(resp)

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding health: %v", err)
	}

	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
	if body.Version == "" {
		t.Error("no version reported — a node that cannot say what it is running " +
			"cannot be diagnosed during the rollout where that matters")
	}
	if body.PolicyVersion == nil {
		t.Fatal("no policyVersion reported")
	}
	// The stack is seeded with an activated policy, so a node serving it reports
	// a real version. Zero would mean it is enforcing nothing, which is a
	// working server that denies everything.
	if *body.PolicyVersion <= 0 {
		t.Errorf("policyVersion = %d, want the activated set — 0 means this node "+
			"is enforcing no policy at all", *body.PolicyVersion)
	}
}

// TestEveryResponseNamesTheRelease.
//
// The header an agent reads to know whether it is talking to a server that
// understands it. On errors as well as successes, which is the whole point: the
// case it exists for is a newer agent asking for a route the server lacks, and
// that answer is a 404. A 404 with no version on it is indistinguishable from a
// typo in a path, so the agent reported a fetch failure and went on serving its
// cache — a degradation that hides itself.
func TestEveryResponseNamesTheRelease(t *testing.T) {
	c := client(t)

	for _, path := range []string{
		"/api/health",
		"/api/auth/me",                // unauthenticated: 401
		"/api/no-such-route-anywhere", // the case this exists for: 404
	} {
		resp := request(t, c, http.MethodGet, hostCardinal, path, "application/json")
		got := resp.Header.Get("X-Cardinal-Version")
		drain(resp)

		if got == "" {
			t.Errorf("%s answered %d with no X-Cardinal-Version — an agent cannot "+
				"tell a route this server lacks from a path it typed wrong",
				path, resp.StatusCode)
		}
	}
}
