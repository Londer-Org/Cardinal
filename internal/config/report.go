package config

import (
	"net/url"
	"strconv"
	"strings"
)

// What this deployment is actually configured to do, and where each answer came
// from.
//
// A read-only report, and deliberately not an editor. Most of this file cannot
// move into the database — the DSN is what reads the database, the listen
// address is needed to bind, and the three encryption keys decrypt what is
// stored, so keeping them there would be taping the key to the door. Of the
// rest, changing `rp_id` stops every registered passkey working and changing
// `public_url` changes the issuer every token carries. Those should be hard.
//
// What was missing was not the ability to change them. It was the ability to
// see them: whether a value was set or defaulted, and — the reason this exists —
// whether anything reads it at all. Two settings in this file were parsed,
// validated and never used by anything, and it took an audit to notice.

// Setting is one configured value as the running server sees it.
type Setting struct {
	// Section and Name are the TOML path, so what is shown can be found.
	Section string `json:"section"`
	Name    string `json:"name"`

	// Value is rendered for reading, never for round-tripping. A secret is
	// reported as whether it is set and nothing more.
	Value string `json:"value"`

	// Source is where the value came from: the file, the environment, or a
	// default nobody chose. The last is the interesting one — it is how a
	// deployment discovers it is relying on something it never decided.
	Source string `json:"source"`

	// Secret marks a value that is withheld. The name and source still show,
	// because "is the signing key set, and did it come from the file" is a
	// question worth answering without answering the other one.
	Secret bool `json:"secret"`

	// Ignored marks a setting nothing reads.
	//
	// The reason for this report. A setting that is parsed, validated and then
	// unused is worse than a missing one: it reads as supported, and somebody
	// tunes it and believes the tuning happened.
	Ignored string `json:"ignored,omitempty"`
}

// Where a value came from. The last is the interesting one: it means nobody
// decided, and the deployment is relying on a number this project picked.
const (
	SourceFile        = "file"
	SourceEnvironment = "environment"
	SourceDefault     = "default"
)

// ignored lists settings nothing reads, and why.
//
// Hand-maintained, and kept honest by TestIgnoredSettingsAreStillIgnored, which
// fails when an entry here starts being used — because a list of known problems
// that quietly stops being true is the same kind of lie it exists to expose.
var ignored = map[string]string{
	"database.max_conns": "the pool is built from the DSN alone; this is never applied",
	"database.conn_max_lifetime": "the pool is built from the DSN alone; this is never " +
		"applied",
	"recovery.email_enabled": "no recovery email is implemented — this enables nothing",
	"recovery.email_domains": "read only by the validation of email_enabled, which " +
		"enables nothing",
}

// Report describes the running configuration.
func (c *Config) Report() []Setting {
	fromFile := c.defined
	idle, absolute := c.Sessions.Effective()
	posix := c.POSIX.Effective()

	add := func(out []Setting, section, name, value string, secret bool) []Setting {
		source := SourceDefault
		if fromFile != nil && fromFile(section, name) {
			source = SourceFile
		}
		return append(out, Setting{
			Section: section, Name: name, Value: value,
			Source: source, Secret: secret,
			Ignored: ignored[section+"."+name],
		})
	}

	var out []Setting
	out = add(out, "server", "listen", c.Server.Listen, false)
	out = add(out, "server", "public_url", c.Server.PublicURL, false)
	out = add(out, "server", "cookie_domain", c.Server.CookieDomain, false)
	out = add(out, "server", "trusted_proxies",
		strings.Join(c.Server.TrustedProxies, ", "), false)

	// Host and database, never the credentials. A connection string is the one
	// value in this file that carries a password inline, and a page that shows
	// it is a page that leaks one to whoever is behind the reader.
	out = add(out, "database", "dsn", redactDSN(c.Database.DSN), true)
	out = add(out, "database", "max_conns", strconv.Itoa(c.Database.MaxConns), false)
	out = add(out, "database", "conn_max_lifetime", c.Database.ConnMaxLifetime.String(), false)

	out = add(out, "webauthn", "rp_id", c.WebAuthn.RPID, false)
	out = add(out, "webauthn", "rp_display_name", c.WebAuthn.RPDisplayName, false)
	out = add(out, "webauthn", "origins", strings.Join(c.WebAuthn.Origins, ", "), false)

	out = add(out, "sessions", "idle", idle.String(), false)
	out = add(out, "sessions", "absolute", absolute.String(), false)

	out = add(out, "posix", "range_low", strconv.Itoa(posix.Low), false)
	out = add(out, "posix", "range_high", strconv.Itoa(posix.High), false)

	out = add(out, "recovery", "email_enabled", strconv.FormatBool(c.Recovery.EmailEnabled), false)
	out = add(out, "recovery", "email_domains",
		strings.Join(c.Recovery.EmailDomains, ", "), false)

	out = add(out, "oidc", "enabled", strconv.FormatBool(c.OIDC.Enabled), false)
	out = add(out, "oidc", "signing_key_encryption_key",
		isSet(c.OIDC.SigningKeyEncryptionKey), true)

	out = add(out, "ssh", "enabled", strconv.FormatBool(c.SSH.Enabled), false)
	out = add(out, "ssh", "ca_encryption_key", isSet(c.SSH.CAEncryptionKey), true)

	out = add(out, "x509", "enabled", strconv.FormatBool(c.X509.Enabled), false)
	out = add(out, "x509", "ca_encryption_key", isSet(c.X509.CAEncryptionKey), true)
	out = add(out, "x509", "public_url", c.X509.PublicURL, false)

	return out
}

// isSet answers the only question worth answering about a secret.
func isSet(v string) string {
	if v == "" {
		return "not set"
	}
	return "set"
}

// redactDSN keeps the parts that identify a database and drops the parts that
// open it.
//
// Not a regex over the string. A DSN can carry the password in the userinfo or
// in a query parameter, and a pattern that catches one spelling and not the
// other is how a credential ends up on a page while somebody believes it was
// handled.
func redactDSN(dsn string) string {
	if dsn == "" {
		return "not set"
	}
	u, err := url.Parse(dsn)
	if err != nil {
		// Unparseable means unknown shape, which means no claim can be made
		// about which part is the secret.
		return "set (unreadable)"
	}
	if u.User != nil {
		if name := u.User.Username(); name != "" {
			u.User = url.User(name)
		} else {
			u.User = nil
		}
	}
	q := u.Query()
	for _, key := range []string{"password", "sslpassword"} {
		if q.Has(key) {
			q.Set(key, "…")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
