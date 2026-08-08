// Package mail renders and delivers notification email.
//
// Notification, and nothing else. ADR 0009 is explicit that recovery email is
// "never for administrators, never alone", and requireDeviceBound exists so
// that only a passkey can change what authenticates as you. A mailed code able
// to authorise either would make whoever runs the mail server able to take over
// any account, so nothing here grants anything.
//
// What it buys instead is detection. Somebody who receives "a passkey was added
// to your account" and did not add one has found out — which is worth a great
// deal and costs nothing in trust.
package mail

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// Kind identifies a message, and is what a deployment overrides.
type Kind string

// The messages this version can send. Each is something that happened to an
// account, and none of them authorises anything.
const (
	KindPasskeyRegistered Kind = "passkey.registered"
	KindPasskeyRevoked    Kind = "passkey.revoked"
	KindRecoveryCodeUsed  Kind = "recovery.code_used"
	KindRecoveryApproved  Kind = "recovery.approved"
	KindInvitationIssued  Kind = "invitation.issued"
	KindTest              Kind = "test"
)

// Template is one message's wording.
type Template struct {
	Subject string
	Body    string
}

// builtin is what ships, and what a deployment falls back to.
//
// Plain text. An HTML message from an identity system is a message that looks
// like every phishing attempt its recipients have been trained to distrust, and
// the things worth saying here are short enough not to need layout.
//
// Each says what happened, when, and what to do if it was not you. That last
// line is the entire point of sending it.
var builtin = map[Kind]Template{
	KindPasskeyRegistered: {
		Subject: "A passkey was added to your {{.Product}} account",
		Body: `A new passkey was added to your account ({{.Login}}) on {{.When}}.

If this was you, there is nothing to do.

If this was not you, somebody else can now sign in as you. Remove it and review
your other passkeys at once:

  {{.ConsoleURL}}/access/passkeys
`,
	},
	KindPasskeyRevoked: {
		Subject: "A passkey was removed from your {{.Product}} account",
		Body: `A passkey was removed from your account ({{.Login}}) on {{.When}}.

If this was you, there is nothing to do.

If this was not you, whoever did it may be trying to lock you out. Check what is
left on your account:

  {{.ConsoleURL}}/access/passkeys
`,
	},
	KindRecoveryCodeUsed: {
		Subject: "A recovery code was used on your {{.Product}} account",
		Body: `One of your recovery codes was used on {{.When}} to set up a new passkey for
your account ({{.Login}}).

If this was you, cross that code off your list — each one works only once.

If this was not you, somebody has your recovery codes. Sign in and generate a new
set, which invalidates every old one:

  {{.ConsoleURL}}/access/passkeys
`,
	},
	KindRecoveryApproved: {
		Subject: "Your {{.Product}} account access was restored",
		Body: `Two administrators approved restoring access to your account ({{.Login}}) on
{{.When}}. You can now set up a passkey again.

If this was not you, tell whoever administers {{.Product}} — two people agreed to
it, and one of them may have been misled.
`,
	},
	KindInvitationIssued: {
		Subject: "Set up your {{.Product}} account",
		Body: `An account has been created for you ({{.Login}}).

Set up your passkey here. The link works once and expires:

  {{.URL}}

If this was not you, you can ignore it — nothing happens until the link is used,
and it expires on its own.
`,
	},
	KindTest: {
		Subject: "{{.Product}} notification email is working",
		Body: `This is a test, sent because somebody asked for one on {{.When}}.

If you are reading it, the relay settings are right.
`,
	},
}

// Data is what a template may refer to.
//
// Deliberately small, and deliberately without anything an attacker chooses. A
// message that interpolated, say, a device name supplied during registration
// would let somebody put their own words into mail this deployment sends and
// signs its name to.
type Data struct {
	// Product is what to call this deployment. "Cardinal" unless set.
	Product string

	Login string
	When  string

	// ConsoleURL is where the account lives, so every "if this was not you"
	// ends somewhere actionable.
	ConsoleURL string

	// URL is the one-time link, for messages that carry one.
	URL string
}

// Render produces a subject and body, preferring a deployment's override.
func Render(kind Kind, override *Template, data Data) (subject, body string, err error) {
	tmpl, ok := builtin[kind]
	if !ok {
		return "", "", fmt.Errorf("mail: no template for %q", kind)
	}
	if override != nil {
		tmpl = *override
	}
	if data.Product == "" {
		data.Product = "Cardinal"
	}

	subject, err = render(string(kind)+":subject", tmpl.Subject, data)
	if err != nil {
		return "", "", err
	}
	body, err = render(string(kind)+":body", tmpl.Body, data)
	if err != nil {
		return "", "", err
	}
	return subject, body + signature(data), nil
}

// signature is appended to every message and is not overridable.
//
// Two lines, and they are the reason it cannot be edited away. A recipient has
// to be able to tell what sent this and about which account, because a message
// that could be reworded into something unattributable is a phishing template
// with a deployment's own relay behind it.
func signature(data Data) string {
	var b strings.Builder
	b.WriteString("\n--\n")
	fmt.Fprintf(&b, "Sent by %s regarding the account %s.\n", data.Product, data.Login)
	if data.ConsoleURL != "" {
		fmt.Fprintf(&b, "%s\n", data.ConsoleURL)
	}
	b.WriteString("You cannot reply to this message to change anything about your account.\n")
	return b.String()
}

// Builtin returns the shipped wording for a kind, for the console to show
// beside an override and for `cardinal mail templates`.
func Builtin(kind Kind) (Template, bool) {
	t, ok := builtin[kind]
	return t, ok
}

// Kinds lists every message this version can send, in a stable order.
func Kinds() []Kind {
	return []Kind{
		KindPasskeyRegistered, KindPasskeyRevoked,
		KindRecoveryCodeUsed, KindRecoveryApproved,
		KindInvitationIssued, KindTest,
	}
}

func render(name, text string, data Data) (string, error) {
	// text/template, not html/template. These are plain-text messages, and
	// html/template would escape an apostrophe into an entity that arrives
	// looking like a mistake.
	t, err := template.New(name).Option("missingkey=error").Parse(text)
	if err != nil {
		return "", fmt.Errorf("mail: parsing %s: %w", name, err)
	}
	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return "", fmt.Errorf("mail: rendering %s: %w", name, err)
	}
	return strings.TrimSpace(out.String()), nil
}
