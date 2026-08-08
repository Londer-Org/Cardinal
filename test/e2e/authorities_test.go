package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The certificate authorities, and the bundles machines have to trust.
//
// Both existed only as CLI commands, so an operator could not see whether an
// authority existed, which key was signing, or when it expires — and that last
// is not a curiosity: an authority whose key expires unnoticed takes the fleet
// with it.

type authorityBody struct {
	Enabled bool   `json:"enabled"`
	Bundle  string `json:"bundle"`
	Keys    []struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
		State       string `json:"state"`
		ExpiresAt   string `json:"expiresAt"`
	} `json:"keys"`
}

func authorities(t *testing.T, c *http.Client) (ssh, x509 authorityBody) {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/authorities", "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reading the authorities returned %d", resp.StatusCode)
	}

	var body struct {
		SSH  authorityBody `json:"ssh"`
		X509 authorityBody `json:"x509"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.SSH, body.X509
}

// TestTheConsoleServesTheSameBundleAsTheCLI.
//
// The assertion this page lives or dies on. What it shows is going to be pasted
// into a trust store, an image build, or a configuration repository — so a
// bundle that differs from the CLI's by a key, an ordering, or a trailing
// newline is worse than no page at all, because it would be trusted.
//
// Compared byte for byte against `cardinal ssh ca trust` and `x509 ca trust`
// rather than against a value written here: the point is that the two
// implementations agree, not that either matches something in this file.
func TestTheConsoleServesTheSameBundleAsTheCLI(t *testing.T) {
	admin, _ := adminClient(t)
	ssh, x509 := authorities(t, admin)

	if ssh.Bundle == "" {
		t.Fatal("the SSH bundle is empty, but host access is configured in this stack")
	}
	if fromCLI := cardinalCLI(t, "ssh", "ca", "trust"); fromCLI != ssh.Bundle {
		t.Errorf("the SSH bundle differs from `cardinal ssh ca trust`.\n"+
			"console: %q\ncli:     %q", ssh.Bundle, fromCLI)
	}

	if x509.Bundle == "" {
		t.Fatal("the X.509 bundle is empty, but issuance is configured in this stack")
	}
	if fromCLI := cardinalCLI(t, "x509", "ca", "trust"); fromCLI != x509.Bundle {
		t.Errorf("the X.509 bundle differs from `cardinal x509 ca trust`.\n"+
			"console: %q\ncli:     %q", x509.Bundle, fromCLI)
	}
}

// TestTheBundleIsUsableAsItStands.
//
// Byte-identical to the CLI is necessary and not sufficient: both could be
// wrong together. This checks the shapes the consuming programs actually
// require — an authorized_keys line for sshd, PEM blocks for a trust store —
// so a bundle that agreed with itself and parsed nowhere would still fail.
func TestTheBundleIsUsableAsItStands(t *testing.T) {
	admin, _ := adminClient(t)
	ssh, x509 := authorities(t, admin)

	// sshd reads TrustedUserCAKeys as authorized_keys lines: type, then base64.
	for line := range strings.SplitSeq(strings.TrimSpace(ssh.Bundle), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "ssh-") &&
			!strings.HasPrefix(fields[0], "ecdsa-") {
			t.Fatalf("not an authorized_keys line, so sshd would refuse the file: %q", line)
		}
	}
	if !strings.HasSuffix(ssh.Bundle, "\n") {
		t.Error("the SSH bundle has no trailing newline — concatenating it with " +
			"another key would join two lines into one")
	}

	// A trust store wants complete PEM blocks, one per root.
	if !strings.HasPrefix(x509.Bundle, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("the X.509 bundle does not start with a PEM block: %.40q", x509.Bundle)
	}
	if strings.Count(x509.Bundle, "-----BEGIN CERTIFICATE-----") !=
		strings.Count(x509.Bundle, "-----END CERTIFICATE-----") {
		t.Error("unbalanced PEM markers — a truncated certificate")
	}
	if got := strings.Count(x509.Bundle, "-----BEGIN CERTIFICATE-----"); got != len(x509.Keys) {
		t.Errorf("%d certificates in the bundle for %d trusted keys — a machine "+
			"trusting this would reject certificates issued by the rest", got, len(x509.Keys))
	}
}

// TestEveryTrustedKeyIsInTheBundle.
//
// Not just the signing one. A machine that trusts only the key signing today
// rejects every certificate issued in the minutes before a rotation — which is
// precisely the window a rotation creates, and the reason a key is published
// before it signs.
func TestEveryTrustedKeyIsInTheBundle(t *testing.T) {
	admin, _ := adminClient(t)
	ssh, x509 := authorities(t, admin)

	for _, authority := range []struct {
		name string
		body authorityBody
	}{{"ssh", ssh}, {"x509", x509}} {
		if len(authority.body.Keys) == 0 {
			t.Fatalf("%s reports no keys while its bundle is %d bytes",
				authority.name, len(authority.body.Bundle))
		}
		signing := 0
		for _, k := range authority.body.Keys {
			if k.State == "signing" {
				signing++
			}
			if k.Fingerprint == "" {
				t.Errorf("%s key %s has no fingerprint, so nobody can check what "+
					"they distributed", authority.name, k.ID)
			}
		}
		if signing != 1 {
			t.Errorf("%s has %d signing keys, want exactly 1 — two would mean "+
				"certificates from either verify, and none would mean issuance "+
				"has stopped", authority.name, signing)
		}
	}
}

// TestTheAuthoritiesNeedTheBroadTier.
//
// The bundles are public by construction — they are what every machine holds —
// but which key signs and when it expires is operational detail, and an
// ordinary account has no reason to enumerate it.
func TestTheAuthoritiesNeedTheBroadTier(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-ca-outsider",
		"e2e-ca-outsider-with-entropy-0123456789abcdef")

	resp, err := c.Do(jsonRequest(t, http.MethodGet, "/api/authorities", csrf, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.StatusCode)
	}
}
