package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Security events, against a receiver that is not Cardinal.
//
// Everything else in this stack proves Cardinal agrees with itself. The
// receiver here fetches the JWKS like any receiver would, verifies signatures
// against it, checks the issuer and the audience, and records what it accepted
// — so "a revocation reaches the applications" is a claim something external
// made.
//
// The trigger is the CLI rather than the API, deliberately. The first version
// of this feature emitted from the HTTP handlers, so `cardinal user disable` on
// the server changed the directory and told nobody: two paths, one of them
// unchecked. Events are read from the journal now, which every path commits to,
// and driving this from the CLI is what keeps that true.

type receivedEvent struct {
	Type      string `json:"type"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Audience  string `json:"audience"`
	Timestamp int64  `json:"timestamp"`
	JTI       string `json:"jti"`
}

func receivedEvents(t *testing.T) ([]receivedEvent, []string) {
	t.Helper()

	resp := request(t, client(t), http.MethodGet,
		"events.cardinal.test", "/received", "application/json")
	defer drain(resp)

	var body struct {
		Events   []receivedEvent `json:"events"`
		Rejected []string        `json:"rejected"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Events, body.Rejected
}

// waitForEvent polls the receiver until one arrives for this subject.
//
// Generous against a five-second delivery tick plus the journal read that
// precedes it. Polling rather than sleeping a fixed time, so a fast machine
// does not wait and a slow one does not fail.
func waitForEvent(t *testing.T, subject, eventType string) receivedEvent {
	t.Helper()

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		events, _ := receivedEvents(t)
		for _, e := range events {
			if e.Subject == subject && e.Type == eventType {
				return e
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("no %s arrived for %s — an application would still believe this "+
		"account is good", eventType, subject)
	return receivedEvent{}
}

// TestDisablingAnAccountReachesTheApplications.
//
// The gap this closes. Revoking here ends the session here; an application that
// issued its own from an OIDC login learns nothing until its token expires,
// which for a compromised account is the whole incident.
func TestDisablingAnAccountReachesTheApplications(t *testing.T) {
	login := "e2e-ssf-subject"

	seedSQL(t, `UPDATE entities SET name = name || '-' || id WHERE name = '`+login+`'`)
	cardinalCLI(t, "user", "create", login)

	subject := strings.TrimSpace(seedQuery(t,
		`SELECT id FROM entities WHERE name = '`+login+`'`))
	if subject == "" {
		t.Fatal("the account was not created")
	}

	// Through the CLI, which is the path that reported nothing before events
	// were read from the journal.
	cardinalCLI(t, "user", "disable", login)

	revoked := waitForEvent(t, subject,
		"https://schemas.openid.net/secevent/caep/event-type/session-revoked")

	if revoked.Issuer != "https://id.cardinal.test:8443" {
		t.Errorf("issuer is %q — a receiver compares it against what it discovered",
			revoked.Issuer)
	}
	if revoked.Audience == "" {
		t.Error("no audience: a token any receiver accepts is one that can be replayed")
	}
	if revoked.JTI == "" {
		t.Error("no jti, so a receiver cannot discard a redelivery")
	}
	if revoked.Timestamp == 0 {
		t.Error("no event_timestamp, so a receiver cannot tell a fresh revocation " +
			"from one it is seeing again an hour later")
	}

	// Disabling is also the strongest possible reduction in assurance, and a
	// receiver enforcing its own step-up rules acts on that rather than on a
	// session ending.
	waitForEvent(t, subject,
		"https://schemas.openid.net/secevent/caep/event-type/assurance-level-change")

	// Nothing was refused. The receiver records rejections separately, so a
	// signature that did not verify would show up here rather than as silence.
	if _, rejected := receivedEvents(t); len(rejected) > 0 {
		t.Errorf("the receiver refused %d token(s): %v", len(rejected), rejected)
	}
}

// TestTheTransmitterDescribesItself.
//
// A receiver reads this before it holds any credential, and what matters most
// is the part that says which half is implemented: stream management is not,
// and finding that out from a 404 during a deprovisioning is the alternative.
func TestTheTransmitterDescribesItself(t *testing.T) {
	resp := request(t, client(t), http.MethodGet, hostCardinal,
		"/.well-known/ssf-configuration", "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the configuration document returned %d", resp.StatusCode)
	}

	var config struct {
		Issuer                   string   `json:"issuer"`
		JWKSURI                  string   `json:"jwks_uri"`
		DeliveryMethodsSupported []string `json:"delivery_methods_supported"`
		Note                     string   `json:"cardinal_note"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		t.Fatal(err)
	}

	if config.Issuer != "https://id.cardinal.test:8443" {
		t.Errorf("issuer is %q; it must match the OIDC one exactly, because a "+
			"receiver compares tokens against what it discovered", config.Issuer)
	}
	// The same JWKS that verifies ID tokens, so security events need no key
	// distribution of their own.
	if !strings.HasSuffix(config.JWKSURI, "/oidc/keys") {
		t.Errorf("jwks_uri is %q, not the OIDC key set", config.JWKSURI)
	}
	if len(config.DeliveryMethodsSupported) == 0 {
		t.Error("no delivery method declared, so a receiver cannot tell how it " +
			"will be contacted")
	}
	if !strings.Contains(config.Note, "not implemented") {
		t.Errorf("the note does not say what is missing: %q", config.Note)
	}
}
