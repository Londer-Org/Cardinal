package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// post is a plain POST that does not fail the test on a refusal.
//
// The shared postJSON calls Fatalf on anything past 300, which is right for a
// helper used to set things up and useless here: half of what these tests
// assert is that a request is refused, and with which status.
func post(t *testing.T, c *http.Client, path, csrf, bearer string, body, out any) *http.Response {
	t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		origin(hostCardinal)+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set("X-Cardinal-CSRF", csrf)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decoding %s: %v", path, err)
		}
	}
	return resp
}

// aPublicKey is a fresh key per call. The private half is discarded: these
// tests are about who may be issued a certificate, not about using one.
func aPublicKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPublic)))
}

// Signing a terminal in, and then using what it got.
//
// The whole path `cardinal ssh` walks, minus the click: the console approves,
// the terminal exchanges a code for a session, and that session obtains an SSH
// certificate. The click is the only part left out, and it is the part a
// headless suite cannot make — establishSession seeds what a passkey produces
// for exactly that reason.
//
// This exists because the endpoint underneath it was unreachable for an entire
// phase. It was implemented, tested at the store layer, and wired to nothing —
// so the tests that mattered all passed and no person could obtain a
// certificate by any means.

func verifierPair(secret string) (verifier, hash string) {
	sum := sha256.Sum256([]byte(secret))
	return secret, base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestATerminalCanSignInAndGetACertificate.
func TestATerminalCanSignInAndGetACertificate(t *testing.T) {
	defer hostAccessFixture(t)()
	const machine = "e2e-linux-cli"
	enrolledHostInGroup(t, machine)

	// The seeded session belongs to e2e-user, and the fixture's rule is
	// `context.localAccount == principal.login` — so the account asked for below
	// is this user's own, and this user has to be in the group that may log in.
	// Asking for somebody else's account is a different test, and it is the one
	// the rule exists to refuse.
	posixFixture(t, "user", "e2e-user")
	grantFixture(t, "e2e-linux-users", "e2e-user")

	c := client(t)
	withSession(t, c)
	csrf := csrfToken(t, c)
	verifier, hash := verifierPair("a-secret-this-terminal-never-sends-through-the-browser")

	var approved struct {
		Code      string `json:"code"`
		ExpiresIn int    `json:"expiresIn"`
	}
	resp := post(t, c, "/api/cli/authorize", csrf, "", map[string]string{
		"callback":     "http://127.0.0.1:41234/callback",
		"verifierHash": hash,
	}, &approved)
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approving returned %d, want 200", resp.StatusCode)
	}
	if approved.Code == "" {
		t.Fatal("no code was issued")
	}

	// A separate client, holding no cookie. This is a different process on the
	// same machine, which is the entire premise.
	terminal := client(t)
	var issued struct {
		Token       string `json:"token"`
		DeviceBound bool   `json:"deviceBound"`
	}
	resp = post(t, terminal, "/api/cli/exchange", "", "", map[string]string{
		"code": approved.Code, "verifier": verifier,
	}, &issued)
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchanging returned %d, want 200", resp.StatusCode)
	}
	if !issued.DeviceBound {
		t.Fatal("the terminal's session is not device-bound, so it can obtain nothing")
	}

	// And now the thing it exists for. A bearer token here rather than a
	// cookie: the terminal is not a browser.
	var cert struct {
		Certificate string   `json:"certificate"`
		Principals  []string `json:"principals"`
	}
	resp = post(t, terminal, "/api/ssh/certificate", "", issued.Token, map[string]string{
		"host":         machine,
		"localAccount": "e2e-user",
		"publicKey":    aPublicKey(t),
	}, &cert)
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		refusal, _ := io.ReadAll(resp.Body) //nolint:errcheck // the assertion below reports what mattered
		t.Fatalf("requesting a certificate returned %d, want 200: %s", resp.StatusCode, refusal)
	}
	if !strings.HasPrefix(cert.Certificate, "ssh-ed25519-cert-v01@openssh.com ") {
		t.Errorf("certificate = %.40q, want an OpenSSH certificate", cert.Certificate)
	}
	if len(cert.Principals) != 1 || cert.Principals[0] != "e2e-user" {
		t.Errorf("principals = %v, want exactly [e2e-user] — a certificate naming "+
			"more than the account policy decided would grant more than was asked",
			cert.Principals)
	}
}

// TestACodeIsUselessWithoutTheVerifier.
//
// The property that makes it safe to put the code in a redirect at all: it
// passes through the browser, the address bar and any proxy in between.
func TestACodeIsUselessWithoutTheVerifier(t *testing.T) {
	c := client(t)
	withSession(t, c)
	csrf := csrfToken(t, c)
	_, hash := verifierPair("the real secret")

	var approved struct {
		Code string `json:"code"`
	}
	resp := post(t, c, "/api/cli/authorize", csrf, "", map[string]string{ //nolint:bodyclose // drained below; bodyclose cannot see through the helper
		"callback":     "http://127.0.0.1:41235/callback",
		"verifierHash": hash,
	}, &approved)
	defer drain(resp)

	resp = post(t, client(t), "/api/cli/exchange", "", "", map[string]string{
		"code": approved.Code, "verifier": "a guess",
	}, nil)
	defer drain(resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("exchanging with the wrong verifier returned %d, want 401",
			resp.StatusCode)
	}

	// The failed attempt must not have spent it, or somebody guessing could
	// lock the legitimate terminal out of its own exchange.
	var issued struct {
		Token string `json:"token"`
	}
	resp = post(t, client(t), "/api/cli/exchange", "", "", map[string]string{
		"code": approved.Code, "verifier": "the real secret",
	}, &issued)
	defer drain(resp)
	if resp.StatusCode != http.StatusOK || issued.Token == "" {
		t.Fatalf("the real terminal could not exchange afterwards: %d", resp.StatusCode)
	}
}

// TestACallbackMustBeLoopback.
//
// A redirect carrying a code must not be pointed anywhere else, and "localhost"
// is a name another resolver can answer.
func TestACallbackMustBeLoopback(t *testing.T) {
	c := client(t)
	withSession(t, c)
	csrf := csrfToken(t, c)
	_, hash := verifierPair("secret")

	for _, callback := range []string{
		"https://evil.example/steal",
		"http://localhost:41236/callback",
		"http://10.0.0.5:41236/callback",
		"http://127.0.0.1/callback",
	} {
		t.Run(callback, func(t *testing.T) {
			resp := post(t, c, "/api/cli/authorize", csrf, "", map[string]string{
				"callback": callback, "verifierHash": hash,
			}, nil)
			defer drain(resp)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("returned %d, want 400 — this is where a code is handed over",
					resp.StatusCode)
			}
		})
	}
}
