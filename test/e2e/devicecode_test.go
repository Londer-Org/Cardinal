package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Signing a terminal in from a device that is not this one.
//
// The loopback flow needs the browser and the CLI to share a loopback
// interface, which is false the moment the terminal is on a server somebody is
// SSH'd into: the approval goes to 127.0.0.1 on the machine the browser runs
// on. This one has the terminal ask first and be approved from anywhere.

type deviceStartBody struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int    `json:"expiresIn"`
	Interval                int    `json:"interval"`
}

type deviceCollectBody struct {
	Status      string `json:"status"`
	Token       string `json:"token"`
	DeviceBound bool   `json:"deviceBound"`
}

// TestATerminalIsSignedInFromAnotherDevice.
//
// The whole flow, in the order a person does it: the terminal asks, prints a
// code, and gets nothing; somebody with a browser looks the code up and
// approves it; the terminal's next poll returns a session that works.
func TestATerminalIsSignedInFromAnotherDevice(t *testing.T) {
	terminal := client(t)
	start := deviceStart(t, terminal)

	if start.DeviceCode == "" || start.UserCode == "" {
		t.Fatalf("starting a device sign-in returned nothing usable: %+v", start)
	}
	if start.DeviceCode == start.UserCode {
		t.Fatal("the code the terminal keeps and the code a person reads are the " +
			"same value, so shoulder-surfing the short one is enough")
	}
	if len(start.UserCode) > 12 {
		t.Errorf("the user code is %d characters; it has to be read aloud", len(start.UserCode))
	}
	if !strings.Contains(start.VerificationURIComplete, start.UserCode) {
		t.Error("the complete verification URI does not carry the code")
	}

	// Nobody has approved it, so the terminal waits rather than failing.
	if status, body := deviceCollect(t, terminal, start.DeviceCode, deviceVerifier); status != http.StatusAccepted {
		t.Fatalf("polling before approval returned %d, want 202: %+v", status, body)
	} else if body.Status != "pending" {
		t.Errorf("polling before approval said %q, not pending", body.Status)
	}

	// A person, on some other device, with a browser and a session.
	approver, csrf := adminClient(t)
	pending := devicePending(t, approver, start.UserCode)
	if pending.RequestedFrom == "" {
		t.Error("the approval screen is told nothing about where the request came " +
			"from, which is the only thing it can show that the terminal did not choose")
	}

	if status := deviceApprove(t, approver, csrf, start.UserCode); status != http.StatusNoContent {
		t.Fatalf("approving returned %d", status)
	}

	status, body := deviceCollect(t, terminal, start.DeviceCode, deviceVerifier)
	if status != http.StatusOK {
		t.Fatalf("collecting after approval returned %d", status)
	}
	if body.Token == "" {
		t.Fatal("collecting returned no session")
	}
	if !body.DeviceBound {
		t.Error("the session is not device-bound, so it inherited less than the " +
			"ceremony that authorised it — and policy will refuse it an SSH certificate")
	}

	// The session is real: it answers as the person who approved it.
	me := whoami(t, terminal, body.Token)
	if me != "e2e-admin" {
		t.Errorf("the terminal is signed in as %q, and e2e-admin approved it", me)
	}
}

// TestADeviceCodeIsSingleUse.
//
// A second terminal holding the same code — because it was logged, or shared —
// must get nothing.
func TestADeviceCodeIsSingleUse(t *testing.T) {
	terminal := client(t)
	start := deviceStart(t, terminal)

	approver, csrf := adminClient(t)
	devicePending(t, approver, start.UserCode)
	deviceApprove(t, approver, csrf, start.UserCode)

	if status, _ := deviceCollect(t, terminal, start.DeviceCode, deviceVerifier); status != http.StatusOK {
		t.Fatalf("the first collection returned %d", status)
	}
	if status, _ := deviceCollect(t, terminal, start.DeviceCode, deviceVerifier); status == http.StatusOK {
		t.Error("the same device code was collected twice")
	}
}

// TestTheDeviceCodeIsUselessWithoutTheVerifier.
//
// The user code is read aloud and the device code may end up in a log. Neither
// is enough: the verifier never leaves the terminal's process.
func TestTheDeviceCodeIsUselessWithoutTheVerifier(t *testing.T) {
	terminal := client(t)
	start := deviceStart(t, terminal)

	approver, csrf := adminClient(t)
	devicePending(t, approver, start.UserCode)
	deviceApprove(t, approver, csrf, start.UserCode)

	if status, _ := deviceCollect(t, terminal, start.DeviceCode, "not-the-verifier"); status == http.StatusOK {
		t.Fatal("a device code was exchanged with the wrong verifier, so whoever " +
			"reads one out of a log holds a session")
	}

	// And the real one still works, so the refusal above was about the verifier
	// rather than about the request having been spent.
	if status, _ := deviceCollect(t, terminal, start.DeviceCode, deviceVerifier); status != http.StatusOK {
		t.Error("the correct verifier was refused after a wrong one was tried")
	}
}

// TestApprovingNeedsADeviceBoundSession.
//
// The point of the flow is to hand a terminal what a passkey proved. An access
// token must not be able to bootstrap one, or every rule that refuses tokens is
// one exchange away from being bypassed.
func TestApprovingNeedsADeviceBoundSession(t *testing.T) {
	terminal := client(t)
	start := deviceStart(t, terminal)

	// Seeded here rather than with tokenUser, which mints a *device-bound*
	// session — under it this test passed while asserting nothing, because
	// approving is allowed to any ordinary person holding a real ceremony. What
	// must be refused is a weaker credential, so this makes one.
	weak, csrf := syncedPasskeyClient(t, "e2e-device-outsider",
		"e2e-device-outsider-with-entropy-0123456789")

	if status := deviceApprove(t, weak, csrf, start.UserCode); status == http.StatusNoContent {
		t.Error("a session that is not device-bound approved a terminal, so every " +
			"rule that refuses a weaker credential is one exchange away from bypass")
	}
}

// syncedPasskeyClient holds a session the way a synced passkey leaves one:
// real, current, and not device-bound.
func syncedPasskeyClient(t *testing.T, login, token string) (*http.Client, string) {
	t.Helper()

	seedSQL(t, `INSERT INTO entities (type, name, display_name)
	            VALUES ('user', '`+login+`', 'Device flow outsider')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `DELETE FROM sessions WHERE token_hash = sha256('`+token+`'::bytea)`)
	seedSQL(t, `INSERT INTO sessions
	              (subject_id, token_hash, valid_period, auth_method, auth_at,
	               device_bound, absolute_expiry)
	            SELECT e.id, sha256('`+token+`'::bytea),
	                   tstzrange(now(), now() + interval '1 hour'), 'passkey', now(),
	                   false, now() + interval '7 days'
	              FROM entities e WHERE e.name = '`+login+`'`)

	c := client(t)
	c.Jar.SetCookies(&url.URL{Scheme: "http", Host: hostCardinal},
		[]*http.Cookie{{Name: "cardinal_session", Value: token, Path: "/"}})
	return c, csrfToken(t, c)
}

// TestAnUnknownCodeSaysNothingUseful.
//
// Unknown, expired and already approved are one answer. The difference would
// tell somebody sweeping for live codes when they had found one.
func TestAnUnknownCodeSaysNothingUseful(t *testing.T) {
	approver, _ := adminClient(t)

	resp := request(t, approver, http.MethodGet, hostCardinal,
		"/api/cli/device/ZZZZ-ZZZZ", "application/json")
	defer drain(resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown code returned %d, want 404", resp.StatusCode)
	}
}

// deviceVerifier is the secret a terminal keeps. Fixed here because these tests
// stand in for the terminal.
const deviceVerifier = "e2e-device-verifier-with-plenty-of-entropy-0123456789"

// The hash is what the terminal sends, computed with the same helper the OIDC
// tests use for PKCE: SHA-256, base64url, unpadded.
func deviceStart(t *testing.T, c *http.Client) deviceStartBody {
	t.Helper()

	var out deviceStartBody
	resp := postJSON(t, c, "/api/cli/device", "", map[string]any{ //nolint:bodyclose // postJSON closes the body before returning
		"verifierHash": s256(deviceVerifier),
	}, &out)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("starting a device sign-in returned %d", resp.StatusCode)
	}
	return out
}

func devicePending(t *testing.T, c *http.Client, code string) struct {
	UserCode      string `json:"userCode"`
	RequestedFrom string `json:"requestedFrom"`
} {
	t.Helper()

	var out struct {
		UserCode      string `json:"userCode"`
		RequestedFrom string `json:"requestedFrom"`
	}
	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/cli/device/"+code, "application/json")
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("looking up %s returned %d", code, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func deviceApprove(t *testing.T, c *http.Client, csrf, code string) int {
	t.Helper()

	resp, err := c.Do(jsonRequest(t, http.MethodPost, "/api/cli/device/"+code+"/approve", csrf, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)
	return resp.StatusCode
}

func deviceCollect(t *testing.T, c *http.Client, code, verifier string) (int, deviceCollectBody) {
	t.Helper()

	req := jsonRequest(t, http.MethodPost, "/api/cli/device/collect", "",
		map[string]any{"deviceCode": code, "verifier": verifier})
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	var out deviceCollectBody
	_ = json.NewDecoder(resp.Body).Decode(&out) //nolint:errcheck // the status is the assertion
	return resp.StatusCode, out
}

func whoami(t *testing.T, c *http.Client, token string) string {
	t.Helper()

	req := jsonRequest(t, http.MethodGet, "/api/auth/me", "", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	var out struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.Login
}
