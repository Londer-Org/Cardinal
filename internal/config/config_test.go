package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	c.Recovery = Recovery{EmailDomains: []string{"example.com"}}

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

	// Empty is the honest reading of "I have not told Cardinal where recovery
	// mail goes". It used to be gated on a separate boolean, which meant the
	// check was off for everybody who had not enabled a feature that did not
	// exist — so the domains were listed, the rule was documented, and nothing
	// enforced it.
	t.Run("no constraint when no domains are listed", func(t *testing.T) {
		off := valid()
		off.Recovery = Recovery{}
		if err := off.CheckRelyingPartyDomain("example.com"); err != nil {
			t.Fatalf("the check applied with no recovery domains listed: %v", err)
		}
	})
}

// TestRemovedSettingsAreRefusedNotIgnored.
//
// recovery.email_enabled validated, appeared on the configuration page, and
// enabled nothing for two releases. Removing the field from the struct would
// have made a file still setting it load silently — the same bug, one layer
// further down — so an unread key is a refusal.
//
// It guards every other key too, which is the larger win: a typo in
// `require_pkce` costs a security control and produces no output at all.
func TestRemovedSettingsAreRefusedNotIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cardinal.toml")

	body := `
[server]
listen = "127.0.0.1:8099"
public_url = "https://id.example.com"

[database]
dsn = "postgres://cardinal@localhost:5433/cardinal"

[webauthn]
rp_id = "example.com"
origins = ["https://id.example.com"]

[recovery]
email_enabled = true
email_domains = ["example.com"]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("a removed setting was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "recovery.email_enabled") {
		t.Errorf("the refusal does not name the offending key: %v", err)
	}
	if !strings.Contains(err.Error(), "ADR 0009") {
		t.Errorf("the refusal does not say why the setting went away: %v", err)
	}
}

// TestTheExampleConfigLoads.
//
// The file every deployment starts from, checked against the refusal above:
// shipping an example that Cardinal will not read is a worse first impression
// than shipping none.
func TestTheExampleConfigLoads(t *testing.T) {
	if _, err := Load(filepath.Join("..", "..", "cardinal.example.toml")); err != nil {
		t.Fatalf("cardinal.example.toml does not load: %v", err)
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

// TestSessionClocksMustMakeSenseTogether.
//
// An absolute cap inside the idle window means every session ends at its cap,
// so the idle setting silently does nothing — a configuration that looks like
// two controls and behaves like one.
func TestSessionClocksMustMakeSenseTogether(t *testing.T) {
	c := valid()
	c.Sessions.Idle = Duration(12 * time.Hour)
	c.Sessions.Absolute = Duration(time.Hour)

	err := c.Validate()
	if err == nil {
		t.Fatal("an absolute cap shorter than the idle window was accepted")
	}
	if !strings.Contains(err.Error(), "sessions.absolute") {
		t.Errorf("the error does not name the setting at fault: %v", err)
	}
}

// TestDurationsAreWrittenTheWayPeopleWriteThem.
func TestDurationsAreWrittenTheWayPeopleWriteThem(t *testing.T) {
	cases := map[string]time.Duration{
		"8h":  8 * time.Hour,
		"30m": 30 * time.Minute,
		// Days, because "168h" is a week only after doing the arithmetic.
		"7d": 7 * 24 * time.Hour,
		"1d": 24 * time.Hour,
	}

	for text, want := range cases {
		var d Duration
		if err := d.UnmarshalText([]byte(text)); err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		if d.Duration() != want {
			t.Errorf("%q = %s, want %s", text, d, want)
		}
	}

	for _, bad := range []string{"", "soon", "-1h", "0h", "8"} {
		var d Duration
		if err := d.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("%q was accepted as a duration", bad)
		}
	}
}

// TestSingleLabelCookieDomainIsRefused.
//
// Browsers discard a cookie whose Domain attribute is a public suffix, and
// every single-label name either is one or is treated as one. The failure is
// total and silent: the response carries a perfectly good Set-Cookie, the
// browser keeps nothing, sign-in loops and every mutation fails CSRF, with
// nothing wrong in any log.
//
// Cardinal's own example shipped `cookie_domain = "localhost"` for months.
// net/http/cookiejar accepts it, so the entire end-to-end suite passed —
// including a test whose only purpose was asserting that cookie was right —
// against a console no browser could sign in to. Refusing it at startup is the
// only place this can be caught without a browser.
func TestSingleLabelCookieDomainIsRefused(t *testing.T) {
	for _, tc := range []struct {
		domain string
		ok     bool
	}{
		{"localhost", false},
		{".localhost", false},
		{"test", false},
		{"local", false},
		{"", true}, // host-only, which is a valid choice
		{"example.com", true},
		{".example.com", true},
		{"cardinal.test", true},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			c := valid()
			c.Server.CookieDomain = tc.domain
			// rp_id has to stay covered, or a different rule fires and the
			// subtest passes for the wrong reason.
			if tc.domain != "" {
				c.WebAuthn.RPID = strings.TrimPrefix(tc.domain, ".")
			}

			err := c.Validate()
			mentions := err != nil && strings.Contains(err.Error(), "cookie_domain")
			if tc.ok && mentions {
				t.Fatalf("%q was refused: %v", tc.domain, err)
			}
			if !tc.ok && !mentions {
				t.Fatalf("%q was accepted — a browser would discard every cookie "+
					"and nothing would say so", tc.domain)
			}
		})
	}
}
