package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.londer.be/cardinal/internal/hostclient"
	"golang.org/x/crypto/ssh"
)

// A machine proving which host it is.
//
// The signing rules are implemented twice on purpose — once in the server, once
// in internal/hostclient — because the server must never trust a string a client
// hands it. These tests are the only place the two meet, so if they ever drift,
// this is what says so.
//
// Everything here goes through Traefik, which matters more than it looks: host
// authentication is the one credential in Cardinal that is *not* a cookie or a
// bearer header, and a proxy that mangled the Authorization header or normalised
// the path would break the signature in a way no unit test would notice.

// enrolledHost creates a host, redeems a token for it, and returns the identity
// it authenticates with.
func enrolledHost(t *testing.T, name string) *hostclient.Identity {
	t.Helper()

	// Idempotent by tolerance rather than by check: the suite may have run
	// before against the same stack, and a host that already exists is fine.
	tryCardinalCLI(t, "host", "create", name)

	out := cardinalCLI(t, "host", "enroll", name, "-token")
	token := strings.TrimSpace(out)
	if token == "" {
		t.Fatalf("no enrollment token in output: %q", out)
	}

	return redeemEnrollment(t, token)
}

// redeemEnrollment turns a token into an identity, the way a machine does.
//
// Split out of enrolledHost so a token from anywhere can be redeemed — the
// console issues them too now, and "the console produced a plausible-looking
// string" is a much weaker claim than "the string enrolled a host".
//
// The keypair is generated here rather than passed in, which is the whole
// design: Cardinal never holds a host's private key, so the only thing that can
// produce one is the machine itself.
func redeemEnrollment(t *testing.T, token string) *hostclient.Identity {
	t.Helper()

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"token":%q,"publicKey":%q}`,
		token, string(ssh.MarshalAuthorizedKey(sshPublic)))

	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+"/api/hosts/enroll", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		drain(resp)
		t.Fatalf("enrollment got %d, want 200", resp.StatusCode)
	}
	drain(resp)

	identity := &hostclient.Identity{Server: origin(hostCardinal), Signer: signer}

	// A control, before any test uses this identity to prove something cannot be
	// done. Every refusal below would pass just as happily if signing were
	// broken outright — which is not hypothetical: the first version of this
	// suite reported five green refusals while rejecting every legitimate
	// request too, because the fingerprint contains a colon and the header was
	// split on the wrong one.
	resp = signedGET{signer: signer, path: "/api/hosts/me"}.send(t)
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a correctly signed request got %d, want 200 — every refusal "+
			"asserted after this would be meaningless", resp.StatusCode)
	}

	return identity
}

// signedGET describes a host-signed request, and the ways to bend it.
//
// Written out longhand rather than calling hostclient.Sign, because that
// function is the *correct* client by construction and these tests need an
// incorrect one. Each override below is empty for a well-formed request; every
// test sets exactly one and asserts the server notices.
type signedGET struct {
	signer ssh.Signer
	path   string
	at     time.Time

	claimFingerprint string // header names this key; the signature is still ours
	signMethod       string // the signature covers this method; the request is a GET
	signPath         string // the signature covers this path; the request goes to path
}

func (g signedGET) send(t *testing.T) *http.Response {
	t.Helper()

	fingerprint := ssh.FingerprintSHA256(g.signer.PublicKey())

	claimed := g.claimFingerprint
	if claimed == "" {
		claimed = fingerprint
	}
	signMethod := g.signMethod
	if signMethod == "" {
		signMethod = http.MethodGet
	}
	signPath := g.signPath
	if signPath == "" {
		signPath = g.path
	}

	at := g.at
	if at.IsZero() {
		at = time.Now()
	}
	timestamp := strconv.FormatInt(at.Unix(), 10)

	signature, err := g.signer.Sign(rand.Reader, []byte(strings.Join([]string{
		"cardinal-host-v1", signMethod, signPath, timestamp, fingerprint,
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, origin(hostCardinal)+g.path, nil) //nolint:noctx // bounded by client timeout
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Cardinal-Host %s:%s:%s",
		claimed, timestamp,
		base64.StdEncoding.EncodeToString(ssh.Marshal(signature))))
	req.Header.Set("Accept", "application/json")

	resp, err := client(t).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", g.path, err)
	}
	return resp
}

// TestEnrolledHostAuthenticates — the whole path, end to end.
func TestEnrolledHostAuthenticates(t *testing.T) {
	identity := enrolledHost(t, "e2e-host-01")

	resp, err := identity.Do(t.Context(), client(t), http.MethodGet, "/api/hosts/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200 — an enrolled host did not authenticate", resp.StatusCode)
	}

	var out struct {
		Host        string   `json:"host"`
		HostID      string   `json:"hostId"`
		Fingerprint string   `json:"fingerprint"`
		Groups      []string `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	if out.Host != "e2e-host-01" {
		t.Fatalf("got host %q, want e2e-host-01", out.Host)
	}
	if out.Fingerprint != identity.Fingerprint() {
		t.Fatalf("server named a different key: %s", out.Fingerprint)
	}
	if out.HostID == "" {
		t.Fatal("no host id — the agent needs the stable identifier, not just the name")
	}
}

// TestUnsignedRequestIsRefused — the baseline, and the reason for the rest.
func TestUnsignedRequestIsRefused(t *testing.T) {
	resp := request(t, client(t), http.MethodGet, hostCardinal, "/api/hosts/me", "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 — /api/hosts/me must require a host signature",
			resp.StatusCode)
	}
}

// TestSessionCookieCannotReachAHostEndpoint.
//
// The reason requireHost is a separate middleware. An administrator is the most
// privileged principal in the stack and still must not be able to answer as a
// machine — a host endpoint that accepted a session would let a stolen admin
// cookie impersonate a production host, and the two credentials have completely
// different theft models.
func TestSessionCookieCannotReachAHostEndpoint(t *testing.T) {
	c, _ := adminClient(t)

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/hosts/me", "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 — a session must not authenticate as a host",
			resp.StatusCode)
	}
}

// TestSignatureIsBoundToTheRequest.
//
// A signature over GET /api/hosts/me presented on a different path must not
// verify. Without method and path in the signed string, a captured header would
// authorise anything a host can do — which, once the agent exists, includes
// asking for certificates.
func TestSignatureIsBoundToTheRequest(t *testing.T) {
	identity := enrolledHost(t, "e2e-host-02")

	for _, tc := range []struct {
		name    string
		request signedGET
		why     string
	}{
		{
			"path",
			signedGET{
				signer: identity.Signer, path: "/api/hosts/me",
				signPath: "/api/hosts/somewhere-else",
			},
			"a signature over one path authorised another",
		},
		{
			// Once the agent exists, POST is how a host asks for things —
			// certificates among them. A signature that did not cover the method
			// would let a captured GET be replayed as one of those.
			"method",
			signedGET{
				signer: identity.Signer, path: "/api/hosts/me",
				signMethod: http.MethodPost,
			},
			"a signature over one method authorised another",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.request.send(t)
			defer drain(resp)

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401 — %s", resp.StatusCode, tc.why)
			}
		})
	}
}

// TestStaleAndFutureTimestampsAreRefused.
//
// Both directions. A stale signature is a replay; a future one is a signature
// being held until it becomes valid, which is the same attack with patience.
func TestStaleAndFutureTimestampsAreRefused(t *testing.T) {
	identity := enrolledHost(t, "e2e-host-03")

	for _, tc := range []struct {
		name string
		at   time.Time
	}{
		{"stale", time.Now().Add(-5 * time.Minute)},
		{"future", time.Now().Add(5 * time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := signedGET{signer: identity.Signer, path: "/api/hosts/me", at: tc.at}.send(t)
			defer drain(resp)

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401 — a %s timestamp was accepted",
					resp.StatusCode, tc.name)
			}
		})
	}
}

// TestSignatureCannotBePresentedUnderAnotherFingerprint.
//
// The fingerprint in the header is what the server looks the key up by, so it
// must also be inside the signature. Otherwise a signature made by one host
// could be replayed claiming to be another — the server would verify against the
// claimed host's public key, fail, and that is only true because the *whole*
// header is checked. This test would pass vacuously if the fingerprint were
// merely an index, so it uses two real hosts and swaps them.
func TestSignatureCannotBePresentedUnderAnotherFingerprint(t *testing.T) {
	first := enrolledHost(t, "e2e-host-04")
	second := enrolledHost(t, "e2e-host-05")

	resp := signedGET{
		signer: first.Signer, path: "/api/hosts/me",
		claimFingerprint: second.Fingerprint(),
	}.send(t)
	defer drain(resp)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 — one host's signature authenticated as another",
			resp.StatusCode)
	}
}

// TestReEnrollingInvalidatesTheOldKey.
//
// The rebuilt-machine case. The moment a host enrols again, the key it used
// before must stop working — a disk pulled out of a bin should not still be able
// to ask Cardinal questions as a production host.
func TestReEnrollingInvalidatesTheOldKey(t *testing.T) {
	// enrolledHost has already proved this key works.
	old := enrolledHost(t, "e2e-host-06")
	fresh := enrolledHost(t, "e2e-host-06")

	resp := signedGET{signer: old.Signer, path: "/api/hosts/me"}.send(t)
	defer drain(resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 — the retired key still authenticates", resp.StatusCode)
	}

	resp2 := signedGET{signer: fresh.Signer, path: "/api/hosts/me"}.send(t)
	defer drain(resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200 — the new key does not authenticate", resp2.StatusCode)
	}
}

// TestSpentTokenIsRefused, at the HTTP layer rather than the store's.
func TestSpentTokenIsRefused(t *testing.T) {
	tryCardinalCLI(t, "host", "create", "e2e-host-07")
	token := strings.TrimSpace(cardinalCLI(t, "host", "enroll", "e2e-host-07", "-token"))

	redeem := func() int {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sshPublic, err := ssh.NewPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		body := fmt.Sprintf(`{"token":%q,"publicKey":%q}`,
			token, string(ssh.MarshalAuthorizedKey(sshPublic)))

		req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
			origin(hostCardinal)+"/api/hosts/enroll", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client(t).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer drain(resp)
		return resp.StatusCode
	}

	if got := redeem(); got != http.StatusOK {
		t.Fatalf("first redemption got %d, want 200", got)
	}
	if got := redeem(); got != http.StatusForbidden {
		t.Fatalf("second redemption got %d, want 403 — the token was spendable twice", got)
	}
}
