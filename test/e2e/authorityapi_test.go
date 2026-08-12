package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// Creating an authority key, and choosing which one signs.
//
// The last operation that reached PostgreSQL and nothing else, and the sharpest
// of them: rotation changes what every host in the fleet will accept. Most of
// what follows is therefore about refusals.

type authorityCreated struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	Algorithm   string `json:"algorithm"`
	Active      bool   `json:"active"`
	PublicKey   string `json:"publicKey"`
	Subject     string `json:"subject"`
	Distribute  string `json:"distribute"`
}

// TestCreatingAnAuthorityChangesNothingUntilItIsActivated.
//
// The order the whole design rests on: a CA nothing trusts, issuing
// certificates everything rejects, is a worse failure than not having one. So
// creating must be the safe half — asserted by checking which key is *signing*
// afterwards, not by reading the response.
func TestCreatingAnAuthorityChangesNothingUntilItIsActivated(t *testing.T) {
	c, csrf := adminClient(t)

	beforeSSH, _ := authorities(t, c)
	signingBefore := signingKey(t, beforeSSH)

	var created authorityCreated
	if status := postJSONStatus(t, c, "/api/authorities/ssh", csrf,
		map[string]any{}, &created); status != http.StatusCreated {
		t.Fatalf("creating an SSH authority returned %d, want 201", status)
	}
	if created.ID == "" || created.PublicKey == "" {
		t.Fatalf("a created key came back without an id or a public half: %+v", created)
	}
	if created.Active {
		t.Error("a key nobody asked to activate came back active")
	}

	afterSSH, _ := authorities(t, c)
	if got := signingKey(t, afterSSH); got != signingBefore {
		t.Errorf("creating a key changed which one signs: %s became %s — every "+
			"host still trusting the old one now rejects what this issues",
			signingBefore, got)
	}

	// The new key is nonetheless published, which is the point of publishing
	// before signing: a host that refreshes now already trusts it.
	if !strings.Contains(afterSSH.Bundle, created.PublicKey) {
		t.Error("the created key is not in the trust bundle, so activating it later " +
			"would break every host that had not refreshed in between")
	}
	if !strings.Contains(created.Distribute, created.PublicKey) {
		t.Error("the creation response does not carry what has to be distributed, " +
			"so the operator has to go and find it")
	}
}

// TestRotatingChangesWhichKeySigns.
//
// And the previous one stays trusted, which is what makes a rotation survivable
// on a fleet that has not refreshed yet.
func TestRotatingChangesWhichKeySigns(t *testing.T) {
	c, csrf := adminClient(t)

	var created authorityCreated
	if status := postJSONStatus(t, c, "/api/authorities/ssh", csrf,
		map[string]any{}, &created); status != http.StatusCreated {
		t.Fatalf("creating returned %d", status)
	}

	beforeRotate, _ := authorities(t, c)
	previous := signingKey(t, beforeRotate)

	var rotated struct {
		Active     string `json:"active"`
		Grace      string `json:"grace"`
		Distribute string `json:"distribute"`
	}
	if status := postJSONStatus(t, c, "/api/authorities/ssh/"+created.ID+"/activate", csrf,
		map[string]any{"grace": "72h"}, &rotated); status != http.StatusOK {
		t.Fatalf("rotating returned %d, want 200", status)
	}
	if rotated.Active != created.ID {
		t.Errorf("rotation reports %s active, asked for %s", rotated.Active, created.ID)
	}
	if rotated.Grace != "72h0m0s" {
		t.Errorf("grace came back as %q, asked for 72h", rotated.Grace)
	}

	afterSSH, _ := authorities(t, c)
	if got := signingKey(t, afterSSH); got != created.ID {
		t.Errorf("after rotating, %s signs rather than %s", got, created.ID)
	}

	// Retired and still trusted is the property that makes a rotation
	// survivable: certificates the previous key issued in the last minutes must
	// keep verifying while the fleet catches up.
	stillTrusted := false
	for _, k := range afterSSH.Keys {
		if k.ID == previous {
			stillTrusted = true
			if k.State == "signing" {
				t.Errorf("%s is still signing after rotating away from it", previous)
			}
		}
	}
	if previous != "" && !stillTrusted {
		t.Errorf("the previous key %s left the trust list immediately, so every "+
			"certificate it issued in the last minutes is now rejected", previous)
	}
}

// TestRotatingToAKeyThatDoesNotExistIsRefused.
//
// Worth its own test because of what the store's activate does: it retires
// whatever is currently signing *before* activating the target. An unknown id
// that reached it would leave the fleet with nothing signing at all.
func TestRotatingToAKeyThatDoesNotExistIsRefused(t *testing.T) {
	c, csrf := adminClient(t)

	beforeSSH, _ := authorities(t, c)
	before := signingKey(t, beforeSSH)

	const nobody = "00000000-0000-7000-8000-000000000000"
	if status := postJSONStatus(t, c, "/api/authorities/ssh/"+nobody+"/activate", csrf,
		map[string]any{}, nil); status != http.StatusNotFound {
		t.Errorf("rotating to an unknown key returned %d, want 404", status)
	}
	if status := postJSONStatus(t, c, "/api/authorities/ssh/not-a-uuid/activate", csrf,
		map[string]any{}, nil); status != http.StatusNotFound {
		t.Errorf("rotating to a malformed id returned %d, want 404", status)
	}

	afterSSH, _ := authorities(t, c)
	if after := signingKey(t, afterSSH); after != before {
		t.Errorf("a refused rotation still changed the signing key from %s to %s — "+
			"the fleet was left signing with something nobody chose", before, after)
	}
}

// TestAnAbsurdGraceIsRefused.
//
// A grace period is how long a key nobody signs with stays trusted, which is a
// window in which a stolen retired key still verifies.
func TestAnAbsurdGraceIsRefused(t *testing.T) {
	c, csrf := adminClient(t)

	var created authorityCreated
	postJSONStatus(t, c, "/api/authorities/ssh", csrf, map[string]any{}, &created)

	for _, grace := range []string{"9000h", "-1h", "soon"} {
		status := postJSONStatus(t, c, "/api/authorities/ssh/"+created.ID+"/activate", csrf,
			map[string]any{"grace": grace}, nil)
		if status != http.StatusBadRequest {
			t.Errorf("grace=%q returned %d, want 400", grace, status)
		}
	}
}

// TestAnX509AuthorityNeedsASubject.
//
// It is what every certificate this authority issues names as its issuer, and
// an empty one produces a root that tools display as blank.
func TestAnX509AuthorityNeedsASubject(t *testing.T) {
	c, csrf := adminClient(t)

	if status := postJSONStatus(t, c, "/api/authorities/x509", csrf,
		map[string]any{}, nil); status != http.StatusBadRequest {
		t.Errorf("creating an X.509 authority with no subject returned %d, want 400", status)
	}

	var created authorityCreated
	if status := postJSONStatus(t, c, "/api/authorities/x509", csrf,
		map[string]any{"subject": "Cardinal e2e Root"}, &created); status != http.StatusCreated {
		t.Fatalf("creating with a subject returned %d, want 201", status)
	}
	if created.Subject != "Cardinal e2e Root" {
		t.Errorf("the authority came back with subject %q", created.Subject)
	}
	if !strings.Contains(created.Distribute, "BEGIN CERTIFICATE") {
		t.Error("the creation response carries no PEM to distribute")
	}
}

// TestAuthorityAdministrationNeedsTheBroadTier.
//
// Creating a key is one press from signing every host login in the fleet.
func TestAuthorityAdministrationNeedsTheBroadTier(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-ca-outsider",
		"e2e-ca-outsider-with-entropy-0123456789abcd")

	for _, path := range []string{"/api/authorities/ssh", "/api/authorities/x509"} {
		if status := postJSONStatus(t, c, path, csrf,
			map[string]any{"subject": "nope"}, nil); status != http.StatusForbidden {
			t.Errorf("an ordinary account reached %s: got %d, want 403", path, status)
		}
	}
}

// signingKey is the one key in the signing state.
//
// It fails rather than returning "" when there is none, which the first version
// of this did — and every comparison it fed then succeeded by comparing two
// empty strings. A helper that reports "nothing signs" as an ordinary value
// makes an authority with no signing key indistinguishable from one that never
// changed.
func signingKey(t *testing.T, a authorityBody) string {
	t.Helper()

	for _, k := range a.Keys {
		if k.State == "signing" {
			return k.ID
		}
	}
	t.Fatalf("no key is signing, out of %d — the fleet has nothing to verify against",
		len(a.Keys))
	return ""
}
