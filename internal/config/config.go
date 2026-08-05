// Package config loads and validates Cardinal's configuration.
//
// Two principles run through this file.
//
// First, **no unsafe defaults.** Values whose wrong choice is a security
// problem — the WebAuthn relying party, the break-glass key — have no default
// at all. Cardinal refuses to start rather than guessing. A system that boots
// with a plausible-looking wrong value is worse than one that will not boot.
//
// Second, **the config file is a trust anchor.** The break-glass public key
// lives here rather than in the database precisely so that a database
// compromise cannot substitute it and a restore cannot roll it back
// (ADR 0009).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server     Server     `toml:"server"`
	Database   Database   `toml:"database"`
	WebAuthn   WebAuthn   `toml:"webauthn"`
	BreakGlass BreakGlass `toml:"break_glass"`
	Recovery   Recovery   `toml:"recovery"`
}

type Server struct {
	Listen string `toml:"listen"`

	// PublicURL is the externally reachable base URL. Used to build redirect
	// URIs and to cross-check the WebAuthn origin.
	PublicURL string `toml:"public_url"`
}

type Database struct {
	DSN string `toml:"dsn"`

	MaxConns        int           `toml:"max_conns"`
	ConnMaxLifetime time.Duration `toml:"conn_max_lifetime"`
}

// WebAuthn configures the relying party.
//
// RPID is effectively permanent. It is baked into every credential at
// registration, and changing it invalidates every passkey ever issued —
// meaning every user must re-enrol, in person, at once. It therefore has no
// default and no inference from other values: the operator must state it
// deliberately, once, having understood that.
type WebAuthn struct {
	// RPID is the relying party identifier: a bare domain, no scheme, no port.
	// It must be the site's domain or a registrable suffix of it.
	RPID string `toml:"rp_id"`

	// RPDisplayName is what authenticators show the user during a prompt.
	RPDisplayName string `toml:"rp_display_name"`

	// Origins are the exact origins permitted to authenticate, including
	// scheme and port. Listing them explicitly rather than deriving them keeps
	// a misconfigured proxy from silently widening what may authenticate.
	Origins []string `toml:"origins"`
}

type BreakGlass struct {
	// PublicKey is the offline emergency key, cardinal-bg-v1: encoded.
	//
	// Deliberately here and not in the database. See ADR 0009.
	PublicKey string `toml:"public_key"`
}

// Recovery configures account recovery channels.
type Recovery struct {
	// EmailEnabled is off by default. Recovery email makes the mail provider a
	// root of trust for Cardinal, and mail administrators implicitly become
	// Cardinal administrators, so enabling it must be a deliberate act
	// (ADR 0009).
	EmailEnabled bool `toml:"email_enabled"`

	// EmailDomains are the domains acceptable for recovery addresses.
	//
	// These are checked against registered OIDC clients: Cardinal refuses to be
	// the identity provider for a domain it also relies on for recovery, since
	// that creates a circular dependency where the recovery channel fails
	// exactly when it is needed.
	EmailDomains []string `toml:"email_domains"`
}

var (
	ErrMissing = errors.New("config: required value missing")
	ErrInvalid = errors.New("config: invalid value")

	// ErrCircularRecovery means the deployment would depend on Cardinal to
	// reach the channel that recovers Cardinal.
	ErrCircularRecovery = errors.New("config: circular recovery dependency")
)

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	var c Config

	// Defaults are set only where a wrong value is an inconvenience rather than
	// a security problem.
	c.Server.Listen = "127.0.0.1:8080"
	c.Database.MaxConns = 10
	c.Database.ConnMaxLifetime = time.Hour

	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	// The DSN may come from the environment so that a secret need not be
	// written to a file that gets committed, copied, or backed up.
	if dsn := os.Getenv("CARDINAL_DSN"); dsn != "" {
		c.Database.DSN = dsn
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate reports every problem it can find, not just the first.
//
// Configuration errors cluster: an operator setting up WebAuthn for the first
// time typically has three things wrong at once. Reporting them one per restart
// is a miserable way to spend an afternoon.
func (c *Config) Validate() error {
	var problems []error

	if c.Database.DSN == "" {
		problems = append(problems,
			fmt.Errorf("%w: database.dsn (or the CARDINAL_DSN environment variable)", ErrMissing))
	}

	problems = append(problems, c.validateWebAuthn()...)

	if c.BreakGlass.PublicKey == "" {
		problems = append(problems, fmt.Errorf(
			"%w: break_glass.public_key — generate one with `cardinal break-glass generate`. "+
				"Without it there is no way back in if administrative access is lost",
			ErrMissing))
	}

	if c.Recovery.EmailEnabled && len(c.Recovery.EmailDomains) == 0 {
		problems = append(problems, fmt.Errorf(
			"%w: recovery.email_domains must list the acceptable domains when "+
				"recovery.email_enabled is true; an unrestricted recovery domain would "+
				"let any mailbox recover any account", ErrMissing))
	}

	if c.Server.PublicURL != "" {
		if u, err := url.Parse(c.Server.PublicURL); err != nil || u.Host == "" {
			problems = append(problems,
				fmt.Errorf("%w: server.public_url must be an absolute URL", ErrInvalid))
		}
	}

	return errors.Join(problems...)
}

func (c *Config) validateWebAuthn() []error {
	var problems []error

	switch {
	case c.WebAuthn.RPID == "":
		problems = append(problems, fmt.Errorf(
			"%w: webauthn.rp_id — this is baked into every credential and cannot be "+
				"changed later without invalidating every passkey, so it has no default",
			ErrMissing))

	case strings.Contains(c.WebAuthn.RPID, "://"),
		strings.Contains(c.WebAuthn.RPID, ":"),
		strings.Contains(c.WebAuthn.RPID, "/"):
		problems = append(problems, fmt.Errorf(
			"%w: webauthn.rp_id must be a bare domain with no scheme, port or path "+
				"(got %q — try %q)",
			ErrInvalid, c.WebAuthn.RPID, stripToHost(c.WebAuthn.RPID)))
	}

	if len(c.WebAuthn.Origins) == 0 {
		problems = append(problems, fmt.Errorf(
			"%w: webauthn.origins — list the exact origins allowed to authenticate, "+
				"including scheme and port", ErrMissing))
	}

	for _, origin := range c.WebAuthn.Origins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Host == "" {
			problems = append(problems, fmt.Errorf(
				"%w: webauthn.origins entry %q must be an absolute origin such as "+
					"https://id.example.com", ErrInvalid, origin))
			continue
		}
		// An origin that isn't within the RP ID can never authenticate: the
		// browser rejects it. Catching it here beats debugging an opaque
		// browser-side failure later.
		if c.WebAuthn.RPID != "" && !originMatchesRPID(u.Hostname(), c.WebAuthn.RPID) {
			problems = append(problems, fmt.Errorf(
				"%w: webauthn.origins entry %q is not within rp_id %q, so browsers will "+
					"refuse to authenticate against it",
				ErrInvalid, origin, c.WebAuthn.RPID))
		}
	}

	return problems
}

// CheckRelyingPartyDomain enforces the rule from ADR 0009: a recovery channel
// must not depend on the system being recovered.
//
// Called when an OIDC client is registered and again at startup. If Cardinal
// would be the identity provider for a domain it also trusts for account
// recovery, then losing Cardinal loses the recovery channel too — and the
// operator finds out on the day it matters.
//
// This is a refusal rather than a warning because the loop is usually created
// long after the recovery setting was made, by someone changing something else
// entirely.
func (c *Config) CheckRelyingPartyDomain(domain string) error {
	if !c.Recovery.EmailEnabled {
		return nil
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	for _, recoveryDomain := range c.Recovery.EmailDomains {
		rd := strings.ToLower(strings.TrimSpace(recoveryDomain))
		if domain == rd || strings.HasSuffix(domain, "."+rd) {
			return fmt.Errorf(
				"%w: %q is configured as a recovery email domain, so making Cardinal "+
					"its identity provider would mean an outage takes the recovery "+
					"channel with it. Remove it from recovery.email_domains, or do not "+
					"federate this domain to Cardinal",
				ErrCircularRecovery, domain)
		}
	}
	return nil
}

// originMatchesRPID reports whether host is the RP ID or a subdomain of it,
// which is the rule browsers apply.
func originMatchesRPID(host, rpID string) bool {
	host, rpID = strings.ToLower(host), strings.ToLower(rpID)
	return host == rpID || strings.HasSuffix(host, "."+rpID)
}

// stripToHost salvages a bare host from a value that looks like a URL, purely
// to suggest a correction in an error message.
func stripToHost(v string) string {
	if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return strings.SplitN(strings.TrimPrefix(v, "//"), ":", 2)[0]
}

// RecoveryDomainAllowed reports whether an address may be used for recovery.
func (c *Config) RecoveryDomainAllowed(email string) bool {
	if !c.Recovery.EmailEnabled {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	return slices.ContainsFunc(c.Recovery.EmailDomains, func(d string) bool {
		return strings.EqualFold(strings.TrimSpace(d), domain)
	})
}
