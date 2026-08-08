// Package config loads and validates Cardinal's configuration.
//
// Two principles run through this file.
//
// First, **no unsafe defaults.** Values whose wrong choice is a security
// problem — the WebAuthn relying party, the token signing key — have no default
// at all. Cardinal refuses to start rather than guessing. A system that boots
// with a plausible-looking wrong value is worse than one that will not boot.
//
// Second, **the config file is a trust anchor.** The signing-key encryption key
// lives here rather than in the database precisely so that a database
// compromise cannot substitute it and a restore cannot roll it back
// (ADR 0009).
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	// For the POSIX range constants only. They live in store because that is
	// where the SQL constraint enforcing the floor lives, and two statements of
	// the same number are how they come to disagree.
	"go.londer.be/cardinal/internal/store"
)

// Config is the parsed contents of cardinal.toml.
type Config struct {
	Server   Server   `toml:"server"`
	Database Database `toml:"database"`
	WebAuthn WebAuthn `toml:"webauthn"`
	Sessions Sessions `toml:"sessions"`
	Recovery Recovery `toml:"recovery"`
	OIDC     OIDC     `toml:"oidc"`
	SSH      SSH      `toml:"ssh"`
	X509     X509     `toml:"x509"`
	POSIX    POSIX    `toml:"posix"`
}

// X509 configures the certificate authority reached over ACME.
type X509 struct {
	// Enabled turns issuance on. Off by default, like everything else that
	// holds a signing key: an authority nobody has pointed a client at is a key
	// sitting in a database for no reason.
	Enabled bool `toml:"enabled"`

	// CAEncryptionKey encrypts the authority's private key at rest.
	//
	// Its own value, distinct from the SSH and OIDC ones. Whoever holds this
	// can issue a certificate for any name the fleet trusts, and one leaked
	// configuration file must not yield more than one authority (ADR 0021).
	//
	// Generate with `openssl rand -base64 32`.
	CAEncryptionKey string `toml:"ca_encryption_key"`

	// PublicURL is where ACME clients reach Cardinal. Defaults to
	// server.public_url.
	//
	// Its own setting because RFC 8555 §6.1 requires HTTPS and every client
	// enforces it — lego refuses an http directory outright. A deployment
	// serving Cardinal over plain HTTP behind a terminating proxy, or reaching
	// ACME through a different ingress, needs to say so rather than have every
	// client refuse the URLs in its own directory document.
	PublicURL string `toml:"public_url"`
}

// ACMEBaseURL is where ACME clients reach this deployment.
func (x X509) ACMEBaseURL(serverPublicURL string) string {
	if x.PublicURL != "" {
		return x.PublicURL
	}
	return serverPublicURL
}

// SSH configures the certificate authority for host access.
type SSH struct {
	// Enabled turns certificate issuance on. Off by default, like the OIDC
	// provider: a certificate authority nobody has enrolled hosts against is
	// a signing key sitting in a database for no reason.
	Enabled bool `toml:"enabled"`

	// CAEncryptionKey encrypts the authority's private key at rest.
	//
	// Deliberately its own setting rather than reusing the OIDC one. Whoever
	// holds the CA key can mint a certificate for any user on any host, and
	// hosts accept it because that is what the key means — so one leaked
	// configuration file must not yield both the token signer and the fleet
	// (ADR 0021).
	//
	// Generate with `openssl rand -base64 32`.
	CAEncryptionKey string `toml:"ca_encryption_key"`
}

// POSIX configures the uid and gid numbers Cardinal hands out.
//
// One range for both, so a uid can never equal an unrelated gid. The numbers
// are permanent — every file on every disk records them — so this is one of the
// few settings that is genuinely hard to change after the fact. Pick it before
// the first user gets one, and write down why.
type POSIX struct {
	// RangeLow is the first number allocated. Must be at least 65536: below
	// 1000 belongs to the distribution, and systemd claims 61184–65519 for
	// DynamicUser.
	RangeLow int `toml:"range_low"`

	// RangeHigh is the last. Exhausting it stops new users being given a uid,
	// which is a configuration change and not an incident — but one that will
	// happen at the worst moment if the range is set tight.
	RangeHigh int `toml:"range_high"`
}

// Effective resolves the range, applying defaults to whichever end is unset.
//
// Same shape as Sessions.Effective, and for the same reason: a Config built in
// code rather than parsed from a file must behave identically, or validation
// rejects a configuration the server would have accepted.
func (p POSIX) Effective() store.POSIXRange {
	r := store.POSIXRange{Low: p.RangeLow, High: p.RangeHigh}
	if r.Low == 0 {
		r.Low = store.DefaultPOSIXRange.Low
	}
	if r.High == 0 {
		r.High = store.DefaultPOSIXRange.High
	}
	return r
}

// OIDC configures the OpenID Connect provider.
type OIDC struct {
	// Enabled turns the provider on. Off by default: an identity provider
	// nobody has configured clients for is attack surface without a purpose.
	Enabled bool `toml:"enabled"`

	// SigningKeyEncryptionKey encrypts the token-signing key at rest.
	//
	// It lives in configuration rather than the database on purpose: a
	// database read must not be enough. The signing key can forge tokens for
	// every registered application, so storing it in the clear would make a
	// database read a complete compromise of every downstream system —
	// arguably worse than losing the directory itself. With this, an attacker
	// needs both.
	//
	// Generate with `openssl rand -base64 32`. Losing it means every issued
	// token becomes unverifiable and every client must re-fetch the JWKS, so
	// it belongs wherever the rest of the deployment's secrets do.
	SigningKeyEncryptionKey string `toml:"signing_key_encryption_key"`
}

// Server holds how the HTTP listener presents itself: where it listens, what
// public URL it believes it has, and how its cookies are scoped.
type Server struct {
	Listen string `toml:"listen"`

	// PublicURL is the externally reachable base URL. Used to build redirect
	// URIs and to cross-check the WebAuthn origin.
	PublicURL string `toml:"public_url"`

	// TrustedProxies lists the CIDRs (or bare addresses) of reverse proxies
	// permitted to set X-Forwarded-For.
	//
	// Empty means trust nothing, which is the safe default: X-Forwarded-For is
	// attacker-controlled unless a proxy overwrites it, so honouring it
	// unconditionally would let anyone evade rate limiting with a header.
	//
	// Only set this when Cardinal is genuinely unreachable except through the
	// proxy. If anything can connect directly — a pod network, a debug port, a
	// misrouted service — an attacker reaching that path can forge the header
	// and this setting becomes the vulnerability rather than the fix.
	TrustedProxies []string `toml:"trusted_proxies"`

	// CookieDomain scopes the session cookie to a parent domain, so a single
	// sign-in covers every application behind the proxy.
	//
	// Without it the cookie is bound to the host that set it, and a session
	// established at id.example.com is simply not sent to app.example.com —
	// which makes forwardAuth single sign-on impossible. This is the setting
	// that turns "logged into Cardinal" into "logged in".
	//
	// It has a real cost, and it should be understood before being set: a
	// cookie scoped to ".example.com" is sent to EVERY subdomain, including any
	// that hosts untrusted or user-generated content. Anything that can read
	// cookies on any subdomain can take the session. Keep such content on a
	// separate registrable domain, not a subdomain of this one.
	//
	// Empty means host-only, which is correct for a single-application
	// deployment and safe by default.
	CookieDomain string `toml:"cookie_domain"`
}

// Database holds the connection settings for the one datastore (ADR 0004).
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

// Sessions bounds how long being signed in lasts.
//
// Two clocks, and they answer different questions. Idle is "how long may
// somebody stop for before they must prove themselves again" — the number that
// decides whether a walked-away laptop is a problem. Absolute is "how long may
// this session exist at all", which is what stops a stolen cookie living
// forever simply because somebody keeps using it.
//
// Neither governs administration. Changing the directory needs a device-bound
// key used within five minutes regardless of session age, and that rule lives
// in the policy set where it can be read and changed like every other one.
type Sessions struct {
	// Idle defaults to 8 hours: a working day, so signing in once in the
	// morning carries someone through it.
	//
	// The tempting shorter values are the ones that get raised. A control
	// people route around is worse than a looser one they keep, and an hour is
	// long enough to be defeated by lunch. Deployments that genuinely need
	// tighter should set it and mean it.
	Idle Duration `toml:"idle"`

	// Absolute defaults to 7 days and is never extended.
	Absolute Duration `toml:"absolute"`
}

// Effective resolves both clocks, applying defaults to whichever is unset.
func (s Sessions) Effective() (idle, absolute time.Duration) {
	return s.Idle.orDefault(DefaultIdleSession),
		s.Absolute.orDefault(DefaultAbsoluteSession)
}

// Defaults, stated here so configuration and the store cannot disagree about
// what "unset" means.
const (
	DefaultIdleSession     = 8 * time.Hour
	DefaultAbsoluteSession = 7 * 24 * time.Hour
)

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
	// ErrMissing reports that a required configuration value was not supplied.
	ErrMissing = errors.New("config: required value missing")
	// ErrInvalid reports that a configured value is not usable.
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
	c.Sessions.Idle = Duration(DefaultIdleSession)
	c.Sessions.Absolute = Duration(DefaultAbsoluteSession)
	c.Database.ConnMaxLifetime = time.Hour

	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}

	// The DSN may come from the environment so that a secret need not be
	// written to a file that gets committed, copied, or backed up.
	if dsn := os.Getenv("CARDINAL_DSN"); dsn != "" {
		c.Database.DSN = dsn
	}

	// Where this deployment is reached, from the environment.
	//
	// These two are the only settings that embed a scheme, host and port, and
	// they are the ones a container image cannot know: the same image runs
	// behind a load balancer on one host and on a laptop on another. Baking
	// them into a config file means a per-deployment file, or an example that
	// only works on the port its author happened to pick.
	//
	// They also have to agree. public_url is the OIDC issuer, which every token
	// carries and every client compares literally; origins is what WebAuthn
	// checks an assertion against. Overriding one and not the other produces a
	// deployment where sign-in works and tokens are rejected, or the reverse —
	// so Validate() checks the pair whichever way they arrived.
	if publicURL := os.Getenv("CARDINAL_PUBLIC_URL"); publicURL != "" {
		c.Server.PublicURL = publicURL
	}
	if origins := os.Getenv("CARDINAL_WEBAUTHN_ORIGINS"); origins != "" {
		c.WebAuthn.Origins = splitAndTrim(origins)
	}
	if acme := os.Getenv("CARDINAL_X509_PUBLIC_URL"); acme != "" {
		c.X509.PublicURL = acme
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// splitAndTrim reads a comma-separated environment value.
//
// Empty entries are dropped rather than kept as empty origins: a trailing comma
// is a typo, and an empty string in the origins list would be compared against
// a real origin and never match, which reads as WebAuthn being broken.
func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
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
	problems = append(problems, c.validatePOSIX()...)
	problems = append(problems, c.validateX509()...)

	// An absolute cap inside the idle window means every session ends at its
	// cap, so the idle setting silently does nothing — a configuration that
	// looks like two controls and behaves like one.
	//
	// Compared after defaults, because unset means "use the default" everywhere
	// else and one of the two being written is the common case. Comparing the
	// raw values would either reject a config that is fine or miss the pairing
	// that is not.
	idle, absolute := c.Sessions.Effective()
	if absolute <= idle {
		problems = append(problems, fmt.Errorf(
			"%w: sessions.absolute (%s) must exceed sessions.idle (%s), or the "+
				"idle window never applies",
			ErrInvalid, absolute, idle))
	}

	if c.Recovery.EmailEnabled && len(c.Recovery.EmailDomains) == 0 {
		problems = append(problems, fmt.Errorf(
			"%w: recovery.email_domains must list the acceptable domains when "+
				"recovery.email_enabled is true; an unrestricted recovery domain would "+
				"let any mailbox recover any account", ErrMissing))
	}

	for _, cidr := range c.Server.TrustedProxies {
		if _, err := parseTrustedPrefix(strings.TrimSpace(cidr)); err != nil {
			problems = append(problems, fmt.Errorf(
				"%w: server.trusted_proxies entry %q is not a CIDR or address",
				ErrInvalid, cidr))
		}
	}

	// A single-label cookie domain is discarded outright.
	//
	// Browsers refuse a Domain attribute that is a public suffix, and every
	// single-label name either is one (`localhost`, `test`, `local`) or is an
	// intranet name treated the same way. The cookie is dropped without a
	// warning anywhere: the response carries a perfectly good Set-Cookie, the
	// browser keeps nothing, and the next request arrives unauthenticated. Every
	// sign-in then loops and every mutation fails CSRF, with the server
	// reporting exactly what it should and no clue at either end.
	//
	// This shipped in Cardinal's own example for months. Nothing caught it
	// because net/http/cookiejar accepts what browsers reject, so an entire
	// end-to-end suite — including a test whose sole purpose was asserting this
	// cookie was right — passed against a console no browser could sign in to.
	// It was found by driving a real Chrome, which is the only thing that can
	// find it.
	if domain := strings.TrimPrefix(strings.TrimSpace(c.Server.CookieDomain), "."); domain != "" &&
		!strings.Contains(domain, ".") {
		problems = append(problems, fmt.Errorf(
			"%w: server.cookie_domain %q is a single label. Browsers discard "+
				"cookies whose Domain is a public suffix, so no session would ever "+
				"be stored and sign-in would fail with nothing logged anywhere. Use "+
				"a domain with a dot (id.example.com under example.com), or leave "+
				"it empty for host-only cookies — which works for the console but "+
				"not for forwardAuth across sibling hosts",
			ErrInvalid, c.Server.CookieDomain))
	}

	// A cookie domain that does not cover the relying party would produce a
	// session the browser never sends back — a silent, baffling login loop.
	if c.Server.CookieDomain != "" && c.WebAuthn.RPID != "" {
		domain := strings.TrimPrefix(strings.ToLower(c.Server.CookieDomain), ".")
		rpID := strings.ToLower(c.WebAuthn.RPID)
		if domain != rpID && !strings.HasSuffix(rpID, "."+domain) {
			problems = append(problems, fmt.Errorf(
				"%w: server.cookie_domain %q does not cover webauthn.rp_id %q, so the "+
					"session cookie would never be sent back and sign-in would loop",
				ErrInvalid, c.Server.CookieDomain, c.WebAuthn.RPID))
		}
	}

	if c.OIDC.Enabled {
		if c.OIDC.SigningKeyEncryptionKey == "" {
			problems = append(problems, fmt.Errorf(
				"%w: oidc.signing_key_encryption_key — the token-signing key is not "+
					"stored in the clear, so this is required when the provider is "+
					"enabled (generate with `openssl rand -base64 32`)", ErrMissing))
		}
		if c.Server.PublicURL == "" {
			problems = append(problems, fmt.Errorf(
				"%w: server.public_url — it is the OIDC issuer identifier and every "+
					"token carries it, so it cannot be inferred", ErrMissing))
		}
	}

	if c.SSH.Enabled {
		if c.SSH.CAEncryptionKey == "" {
			problems = append(problems, fmt.Errorf(
				"%w: ssh.ca_encryption_key — the certificate authority key is not "+
					"stored in the clear, so this is required when host access is "+
					"enabled (generate with `openssl rand -base64 32`)", ErrMissing))
		}
		// Refused rather than warned about. Sharing the two means one leaked
		// file yields both the token signer and a key that can log into every
		// host as anybody, and a warning is something people read once.
		if c.SSH.CAEncryptionKey != "" &&
			c.SSH.CAEncryptionKey == c.OIDC.SigningKeyEncryptionKey {
			problems = append(problems, fmt.Errorf(
				"%w: ssh.ca_encryption_key is the same value as "+
					"oidc.signing_key_encryption_key — they protect different keys "+
					"and sharing one means a single leaked secret yields both the "+
					"token signer and the SSH certificate authority (ADR 0021)",
				ErrInvalid))
		}
	}

	if c.Server.PublicURL != "" {
		if u, err := url.Parse(c.Server.PublicURL); err != nil || u.Host == "" {
			problems = append(problems,
				fmt.Errorf("%w: server.public_url must be an absolute URL", ErrInvalid))
		}
	}

	return errors.Join(problems...)
}

// validatePOSIX checks the range before any number is handed out.
//
// Worth failing to start over, rather than warning about. A uid is permanent —
// every file on every disk records it — so a range that overlaps the system's
// own accounts does not produce a validation error later, it produces a machine
// where Cardinal's idea of a user and the kernel's disagree.
func (c *Config) validatePOSIX() []error {
	var problems []error

	// Compared after defaults, because unset means "use the default" here as
	// everywhere else, and writing only one end of the range is the common case.
	r := c.POSIX.Effective()

	if r.Low < store.POSIXAllocationFloor {
		problems = append(problems, fmt.Errorf(
			"%w: posix.range_low is %d — below %d belongs to the distribution's "+
				"own accounts and to systemd's DynamicUser reservation",
			ErrInvalid, r.Low, store.POSIXAllocationFloor))
	}
	if r.High <= r.Low {
		problems = append(problems, fmt.Errorf(
			"%w: posix.range_high (%d) must be above posix.range_low (%d)",
			ErrInvalid, r.High, r.Low))
	}

	return problems
}

// validateX509 checks the authority is configured coherently.
func (c *Config) validateX509() []error {
	if !c.X509.Enabled {
		return nil
	}

	var problems []error
	if c.X509.CAEncryptionKey == "" {
		problems = append(problems, fmt.Errorf(
			"%w: x509.ca_encryption_key — the authority key is not stored in the "+
				"clear, so it cannot be created or read without it", ErrMissing))
		return problems
	}

	// Every URL in the directory document is absolute, and a client that
	// fetched it over HTTPS and then found http links would refuse them —
	// correctly. Caught at startup rather than by the first client to try.
	base := c.X509.ACMEBaseURL(c.Server.PublicURL)
	if !strings.HasPrefix(base, "https://") {
		problems = append(problems, fmt.Errorf(
			"%w: ACME requires HTTPS (RFC 8555 §6.1) and %q is not — set "+
				"x509.public_url, or serve Cardinal over HTTPS",
			ErrInvalid, base))
	}

	// Three keys, three values. Sharing one would mean a single leaked
	// configuration file yields the token signer, the fleet's SSH access and
	// the fleet's TLS — which is the concentration ADR 0021 exists to prevent,
	// and it is worth refusing rather than warning about.
	for name, other := range map[string]string{
		"oidc.signing_key_encryption_key": c.OIDC.SigningKeyEncryptionKey,
		"ssh.ca_encryption_key":           c.SSH.CAEncryptionKey,
	} {
		if other != "" && other == c.X509.CAEncryptionKey {
			problems = append(problems, fmt.Errorf(
				"%w: x509.ca_encryption_key is the same value as %s — one leaked "+
					"file must not yield two authorities (ADR 0021)",
				ErrInvalid, name))
		}
	}
	return problems
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

// parseTrustedPrefix accepts a CIDR or a bare address, since operators
// reasonably write either.
func parseTrustedPrefix(s string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
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
