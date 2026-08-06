package config

import (
	"errors"
	"strings"
	"testing"
)

func valid() *Config {
	return &Config{
		Database: Database{DSN: "postgres://localhost/cardinal"},
		WebAuthn: WebAuthn{RPID: "example.com", Origins: []string{"https://id.example.com"}},
	}
}

func TestValidConfigPasses(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("a valid config was rejected: %v", err)
	}
}

// TestNoUnsafeDefaults: values whose wrong choice is a security problem must
// have no default. Cardinal refusing to start is far better than Cardinal
// starting with a plausible-looking wrong value.
func TestNoUnsafeDefaults(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantHas string
	}{
		{"missing rp_id", func(c *Config) { c.WebAuthn.RPID = "" }, "rp_id"},
		{"missing origins", func(c *Config) { c.WebAuthn.Origins = nil }, "origins"},
		{"missing dsn", func(c *Config) { c.Database.DSN = "" }, "database.dsn"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)

			err := c.Validate()
			if err == nil {
				t.Fatal("config started without a value that has no safe default")
			}
			if !errors.Is(err, ErrMissing) {
				t.Fatalf("expected ErrMissing, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantHas) {
				t.Fatalf("error should name %q, got: %v", tc.wantHas, err)
			}
		})
	}
}

// TestRPIDMustBeBareDomain: an rp_id with a scheme or port silently fails at
// the browser, which is a miserable thing to debug. Catch it at startup and
// suggest the fix.
func TestRPIDMustBeBareDomain(t *testing.T) {
	for _, bad := range []string{
		"https://example.com",
		"example.com:8080",
		"example.com/auth",
	} {
		t.Run(bad, func(t *testing.T) {
			c := valid()
			c.WebAuthn.RPID = bad
			c.WebAuthn.Origins = []string{"https://example.com"}

			err := c.Validate()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected rejection of %q, got %v", bad, err)
			}
			if !strings.Contains(err.Error(), "try ") {
				t.Fatal("the error should suggest the corrected value")
			}
		})
	}
}

// TestOriginMustBeWithinRPID: browsers refuse to authenticate an origin outside
// the relying party, so a mismatch is a startup error rather than a runtime
// mystery.
func TestOriginMustBeWithinRPID(t *testing.T) {
	c := valid()
	c.WebAuthn.RPID = "example.com"
	c.WebAuthn.Origins = []string{"https://id.example.com", "https://attacker.test"}

	err := c.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("an origin outside rp_id was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "attacker.test") {
		t.Fatalf("the error should name the offending origin: %v", err)
	}
}

func TestSubdomainOriginsAccepted(t *testing.T) {
	c := valid()
	c.WebAuthn.RPID = "example.com"
	c.WebAuthn.Origins = []string{
		"https://example.com",
		"https://id.example.com",
		"https://login.eu.example.com",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("legitimate subdomain origins were rejected: %v", err)
	}
}

// TestCircularRecoveryRefused is the enforcement of ADR 0009's governing rule:
// a recovery channel must not depend on the system being recovered.
//
// The loop is normally created long after the recovery setting was made, by
// someone federating a mail domain for unrelated reasons. Cardinal must refuse
// rather than warn, because a warning at that moment reaches nobody who is
// thinking about account recovery.
func TestCircularRecoveryRefused(t *testing.T) {
	c := valid()
	c.Recovery = Recovery{EmailEnabled: true, EmailDomains: []string{"example.com"}}

	t.Run("exact domain is refused", func(t *testing.T) {
		err := c.CheckRelyingPartyDomain("example.com")
		if !errors.Is(err, ErrCircularRecovery) {
			t.Fatalf("Cardinal agreed to be the IdP for its own recovery domain: %v", err)
		}
	})

	t.Run("subdomain is refused", func(t *testing.T) {
		// mail.example.com federated to Cardinal still takes the recovery
		// channel down with Cardinal.
		if err := c.CheckRelyingPartyDomain("mail.example.com"); !errors.Is(err, ErrCircularRecovery) {
			t.Fatalf("a subdomain of the recovery domain was accepted: %v", err)
		}
	})

	t.Run("unrelated domain is fine", func(t *testing.T) {
		if err := c.CheckRelyingPartyDomain("grafana.internal"); err != nil {
			t.Fatalf("an unrelated relying party was refused: %v", err)
		}
	})

	t.Run("no constraint when recovery email is off", func(t *testing.T) {
		off := valid()
		off.Recovery = Recovery{EmailEnabled: false, EmailDomains: []string{"example.com"}}
		if err := off.CheckRelyingPartyDomain("example.com"); err != nil {
			t.Fatalf("the check should not apply when recovery email is disabled: %v", err)
		}
	})
}

// TestRecoveryEmailIsOptInWithBoundedDomains: an unrestricted recovery domain
// would let any mailbox anywhere recover any account.
func TestRecoveryEmailIsOptInWithBoundedDomains(t *testing.T) {
	c := valid()
	c.Recovery = Recovery{EmailEnabled: true}

	if err := c.Validate(); !errors.Is(err, ErrMissing) {
		t.Fatalf("recovery email was enabled with no domain restriction: %v", err)
	}

	if valid().Recovery.EmailEnabled {
		t.Fatal("recovery email must be off unless deliberately enabled")
	}
}

func TestRecoveryDomainAllowed(t *testing.T) {
	c := valid()
	c.Recovery = Recovery{EmailEnabled: true, EmailDomains: []string{"example.com", "Example.NET"}}

	cases := map[string]bool{
		"arthur@example.com":      true,
		"arthur@EXAMPLE.com":      true,
		"arthur@example.net":      true,
		"arthur@notexample.com":   false,
		"arthur@mail.example.com": false, // subdomains are not implied
		"not-an-address":          false,
	}
	for addr, want := range cases {
		if got := c.RecoveryDomainAllowed(addr); got != want {
			t.Errorf("RecoveryDomainAllowed(%q) = %v, want %v", addr, got, want)
		}
	}
}

// TestValidateReportsEveryProblem: an operator configuring WebAuthn for the
// first time usually has several things wrong at once, and discovering them one
// restart at a time is a miserable afternoon.
func TestValidateReportsEveryProblem(t *testing.T) {
	empty := &Config{}
	err := empty.Validate()
	if err == nil {
		t.Fatal("an empty config was accepted")
	}
	for _, want := range []string{"database.dsn", "rp_id", "origins"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got:\n%v", want, err)
		}
	}
}
