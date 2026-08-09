package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Building policy rules without writing Cedar.
//
// Cedar remains the only thing enforced. Nothing here is a second source of
// truth: a rule composed by the console or the CLI becomes text in the same
// document, published as an ordinary version, activated the same way and rolled
// back the same way. What this removes is the requirement to hand-edit a file
// and republish it in order to say "these people may log into these machines" —
// which is the sentence policy is written to express and the one thing that
// previously needed an editor.
//
// The hard requirement is that editing must never damage what it did not
// author. A deployment's policy set carries comments explaining why each rule
// exists, and a round trip through a structured form would silently discard
// them — turning a convenience into a way to lose the reasoning behind an
// access decision. So the document is treated as a sequence of chunks and
// rewritten surgically: adding appends, removing drops one chunk, and every
// byte of everything else survives unchanged.
//
// There is deliberately no edit. Changing a rule is removing it and adding the
// replacement, which is the same operation and avoids the case that has no good
// answer: a comment written for the previous version of a rule, still sitting
// above the new one, now describing something that is not there.

// RuleKind is a shape this package can compose and recognise.
type RuleKind string

const (
	// KindWebAccess is who may reach an application through the proxy.
	KindWebAccess RuleKind = "web-access"

	// KindAppAccess is who may sign in to an application over OIDC.
	KindAppAccess RuleKind = "application-access"

	// KindSSHLogin is who may log into which machines, as which local account.
	KindSSHLogin RuleKind = "ssh-login"

	// KindRunAsRoot is who may become root on which machines.
	KindRunAsRoot RuleKind = "run-as-root"

	// KindOther is everything else: a forbid, a step-up rule, anything with a
	// condition this package does not compose. Shown as text and preserved
	// exactly, never rewritten.
	KindOther RuleKind = "other"
)

// Everyone is the principal of a rule that names no group.
//
// A real value rather than an empty string, so a form cannot mean "everybody"
// by leaving a field blank — which is the wrong direction for a mistake to fail
// in when the field decides who gets access.
const Everyone = "everyone"

// AccountOwnLogin means the certificate's principal is the person's own login.
//
// The common case, and the one worth having a name for: a rule permitting an
// arbitrary context.localAccount would let somebody request a certificate
// naming a service account, and the machine would honour it.
const AccountOwnLogin = "@login"

// Anything is the resource of a rule that constrains none.
//
// Named rather than expressed by leaving a field blank, for the same reason as
// Everyone: a form must not be able to mean "all of them" by omission. The
// shipped set contains one of these deliberately — every application may be
// signed in to until somebody narrows it — so this is a shape to display
// honestly rather than one to pretend does not exist.
const Anything = "anything"

// Rule is one policy rule, structured where this package recognises the shape.
type Rule struct {
	// ID is the @id annotation. Every rule has one — the engine refuses a
	// policy set where any does not.
	ID   string
	Kind RuleKind

	// PrincipalGroup is a group identifier, or Everyone.
	PrincipalGroup string

	// ResourceGroup and ResourceApplication are alternatives: a rule names
	// either a group of resources or one application by name.
	ResourceGroup       string
	ResourceApplication string

	// LocalAccounts are the accounts a certificate may name. SSH only.
	//
	// AccountOwnLogin as an entry means the principal's own login. Several are
	// permitted because a deploy user and a service account on the same
	// machines is an ordinary arrangement, and expressing it as two rules
	// duplicates everything except the one field that differs.
	LocalAccounts []string

	// Source is the rule exactly as it appears in the document, including the
	// comments above it. Always populated, including for a recognised rule:
	// this is what is preserved when something else in the document changes.
	Source string

	// Comment is the sentence written above the rule when it is composed.
	//
	// Supplied by the caller because only the caller can resolve an identifier
	// to a name: policy stores `00000000-…-0e5be1` and a person reading the
	// file wants `sre`. Deriving it here would put the identifier in the one
	// place whose entire purpose is to be readable — which the first version of
	// this did, producing comments nobody could use.
	//
	// Empty means derive it, which is right for a test and wrong for anything a
	// person will read.
	Comment string
}

// Composable reports whether this package could render this rule itself.
func (r Rule) Composable() bool { return r.Kind != KindOther }

// actionFor maps a kind to the Cedar action it governs.
var actionFor = map[RuleKind]string{
	KindWebAccess: "AccessURL",
	KindAppAccess: "AccessApplication",
	KindSSHLogin:  "SSHLogin",
	KindRunAsRoot: "RunAsRoot",
}

// Render produces the Cedar text for a rule, with a comment describing it.
//
// The comment is generated rather than left to the author because a rule
// arriving in the file with no explanation is one nobody will dare remove.
// Saying what it does in words is not documentation for its own sake: it is how
// somebody reading the file six months later knows whether it is still wanted.
func Render(r Rule) (string, error) {
	action, ok := actionFor[r.Kind]
	if !ok {
		return "", fmt.Errorf("policy: %q is not a rule this can compose", r.Kind)
	}
	if strings.TrimSpace(r.ID) == "" {
		return "", errors.New("policy: a rule needs an id, so a decision can name it")
	}
	if strings.ContainsAny(r.ID, `"\`) {
		return "", fmt.Errorf("policy: %q cannot be an id", r.ID)
	}

	principal := "principal"
	if r.PrincipalGroup != Everyone && r.PrincipalGroup != "" {
		principal = fmt.Sprintf("principal in Cardinal::Group::%q", r.PrincipalGroup)
	}

	var resource string
	switch {
	case r.ResourceApplication != "":
		resource = fmt.Sprintf("resource == Cardinal::Application::%q", r.ResourceApplication)
	case r.ResourceGroup == Anything:
		resource = "resource"
	case r.ResourceGroup != "":
		resource = fmt.Sprintf("resource in Cardinal::Group::%q", r.ResourceGroup)
	default:
		return "", fmt.Errorf(
			"policy: a %s rule needs a resource — %q if it really is meant to "+
				"cover all of them", r.Kind, Anything)
	}

	comment := r.Comment
	if strings.TrimSpace(comment) == "" {
		comment = describe(r)
	}

	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(comment), "\n") {
		fmt.Fprintf(&b, "// %s\n", strings.TrimSpace(line))
	}
	fmt.Fprintf(&b, "@id(%q)\npermit (\n    %s,\n    action == Cardinal::Action::%q,\n    %s\n)",
		r.ID, principal, action, resource)

	if r.Kind == KindSSHLogin {
		condition, err := accountCondition(r.LocalAccounts)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\nwhen {\n    %s\n}", condition)
	}

	b.WriteString(";\n")
	return b.String(), nil
}

// accountCondition renders the local accounts a certificate may name.
//
// An empty list means the principal's own login, which is the default worth
// having: a rule permitting an arbitrary context.localAccount would let
// somebody request a certificate naming a service account, and the machine
// would honour it.
func accountCondition(accounts []string) (string, error) {
	if len(accounts) == 0 {
		accounts = []string{AccountOwnLogin}
	}

	terms := make([]string, 0, len(accounts))
	for _, account := range accounts {
		if account == AccountOwnLogin {
			// Also what decides which people a host is allowed to know about:
			// cardinal-agent serves POSIX identity only for those a rule
			// reaches, so a host resolves the names of people who may log into
			// it and nobody else.
			terms = append(terms, "context.localAccount == principal.login")
			continue
		}
		if account == "" || strings.ContainsAny(account, `"\`) {
			return "", fmt.Errorf("policy: %q cannot be a local account", account)
		}
		// Never root. Becoming root is a separate action with a stricter rule,
		// and a certificate whose principals included it would have granted it
		// without that rule ever being consulted.
		if account == "root" {
			return "", errors.New(
				"policy: root is granted by a run-as-root rule, not by an SSH " +
					"principal — a certificate naming it would skip the freshness check")
		}
		terms = append(terms, fmt.Sprintf("context.localAccount == %q", account))
	}
	return strings.Join(terms, " || "), nil
}

// describe renders a rule as a sentence, for the generated comment and the UI.
func describe(r Rule) string {
	who := "Anyone who signs in"
	if r.PrincipalGroup != Everyone && r.PrincipalGroup != "" {
		who = "Members of " + r.PrincipalGroup
	}

	what := ""
	switch r.Kind {
	case KindWebAccess:
		what = "may reach"
	case KindAppAccess:
		what = "may sign in to"
	case KindSSHLogin:
		return fmt.Sprintf("%s may log into %s, as %s.",
			who, target(r), accounts(r.LocalAccounts))
	case KindRunAsRoot:
		what = "may become root on"
	case KindOther:
		return "Hand-written."
	}
	return fmt.Sprintf("%s %s %s.", who, what, target(r))
}

func target(r Rule) string {
	switch {
	case r.ResourceApplication != "":
		return r.ResourceApplication
	case r.ResourceGroup == Anything || r.ResourceGroup == "":
		// Said plainly. A rule covering everything reads as an oversight when
		// rendered as a blank, and as a decision when rendered as a sentence.
		return "anything at all"
	default:
		return "anything in " + r.ResourceGroup
	}
}

func accounts(list []string) string {
	if len(list) == 0 {
		return "their own account"
	}
	named := make([]string, 0, len(list))
	for _, account := range list {
		if account == AccountOwnLogin {
			named = append(named, "their own account")
			continue
		}
		named = append(named, account)
	}
	return strings.Join(named, " or ")
}

// Describe is describe, exported for the console and the CLI listing.
func Describe(r Rule) string { return describe(r) }

// Patterns recognising a composed rule.
//
// Matched against a normalised form — comments removed, whitespace collapsed —
// rather than against cedar-go's rendering of the parsed policy. Those two are
// equivalent today, and the normalised text has the property that matters here:
// it does not change when a dependency changes how it prints. A recogniser that
// silently stopped matching would show every rule as hand-written and quietly
// remove the ability to manage them, which is the failure that would be
// hardest to notice.
var (
	// Whitespace is \s* at every junction rather than a literal space. The
	// normalising pass collapses runs to one space but cannot decide where a
	// space belongs: `)` on its own line becomes `" );` and `);` stays `);`,
	// both of which are the same rule. A pattern written against one of those
	// recognises nothing in a file formatted the other way — which is how the
	// first version of this matched none of the eleven rules Cardinal ships.
	rulePattern = regexp.MustCompile(
		`^@id\("([^"]*)"\)\s*permit\s*\(\s*principal` +
			`(?:\s+in\s+Cardinal::Group::"([^"]*)")?\s*,\s*` +
			`action\s*==\s*Cardinal::Action::"([^"]*)"\s*,\s*` +
			`resource(?:\s+in\s+Cardinal::Group::"([^"]*)"` +
			`|\s*==\s*Cardinal::Application::"([^"]*)")?\s*` +
			`\)\s*(?:when\s*\{\s*(.*?)\s*\}\s*)?;$`)

	accountOwnLogin = regexp.MustCompile(`^context\.localAccount\s*==\s*principal\.login$`)
	accountLiteral  = regexp.MustCompile(`^context\.localAccount\s*==\s*"([^"]*)"$`)

	idPattern = regexp.MustCompile(`@id\("([^"]*)"\)`)
)

var kindForAction = map[string]RuleKind{
	"AccessURL":         KindWebAccess,
	"AccessApplication": KindAppAccess,
	"SSHLogin":          KindSSHLogin,
	"RunAsRoot":         KindRunAsRoot,
}

// Parse reads a policy document into rules.
//
// Every rule is returned, recognised or not, in document order and with its
// source text. A caller rewriting the document works from this list, so
// anything this cannot understand still travels through unchanged — which is
// the property that makes it safe to point at a policy set somebody else wrote.
func Parse(document string) ([]Rule, error) {
	chunks, err := split(document)
	if err != nil {
		return nil, err
	}

	rules := make([]Rule, 0, len(chunks))
	for _, c := range chunks {
		rule := Rule{ID: c.id, Kind: KindOther, Source: c.text}
		if r, ok := recognise(c.normalised); ok {
			r.Source = c.text
			rule = r
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func recognise(normalised string) (Rule, bool) {
	m := rulePattern.FindStringSubmatch(normalised)
	if m == nil {
		return Rule{}, false
	}

	kind, ok := kindForAction[m[3]]
	if !ok {
		return Rule{}, false
	}

	r := Rule{
		ID:                  m[1],
		Kind:                kind,
		PrincipalGroup:      m[2],
		ResourceGroup:       m[4],
		ResourceApplication: m[5],
	}
	if r.PrincipalGroup == "" {
		r.PrincipalGroup = Everyone
	}
	if r.ResourceGroup == "" && r.ResourceApplication == "" {
		r.ResourceGroup = Anything
	}

	condition := strings.TrimSpace(m[6])
	switch {
	case condition == "":
		// Only SSH takes a condition, and it always has one: without it the
		// certificate could name any account. A rule of another kind carrying a
		// condition is something this did not write, and recomposing it would
		// drop that condition — so it stays hand-written.
		if kind == KindSSHLogin {
			return Rule{}, false
		}
	case kind != KindSSHLogin:
		return Rule{}, false
	default:
		accounts, ok := parseAccounts(condition)
		if !ok {
			return Rule{}, false
		}
		r.LocalAccounts = accounts
	}

	return r, true
}

// parseAccounts reads the local accounts out of an SSH rule's condition.
//
// Split on || rather than matched whole, so a rule naming three accounts is
// recognised as well as one naming a single account. Anything else in the
// condition — a check on the time of day, a comparison this does not know —
// makes the rule hand-written, which is the safe answer: recomposing it would
// silently drop whatever was not understood.
func parseAccounts(condition string) ([]string, bool) {
	terms := strings.Split(condition, "||")
	out := make([]string, 0, len(terms))

	for _, term := range terms {
		term = strings.TrimSpace(term)
		switch {
		case accountOwnLogin.MatchString(term):
			out = append(out, AccountOwnLogin)
		default:
			m := accountLiteral.FindStringSubmatch(term)
			if m == nil {
				return nil, false
			}
			out = append(out, m[1])
		}
	}
	return out, len(out) > 0
}

// Add appends a rule to a document.
//
// Appended rather than inserted in any particular place, because Cedar's
// evaluation does not depend on order — a forbid beats a permit wherever either
// sits — so ordering is a readability choice, and putting new rules at the end
// is the one that leaves the rest of the file untouched.
func Add(document string, r Rule) (string, error) {
	rendered, err := Render(r)
	if err != nil {
		return "", err
	}

	existing, err := Parse(document)
	if err != nil {
		return "", err
	}
	for _, e := range existing {
		if e.ID == r.ID {
			return "", fmt.Errorf(
				"policy: a rule called %q is already there; remove it first, "+
					"because two decisions cannot both be named the same thing "+
					"in a decision log", r.ID)
		}
	}

	out := strings.TrimRight(document, " \t\n") + "\n\n" + rendered
	if _, err := NewEngine([]byte(out), 0); err != nil {
		return "", fmt.Errorf("policy: the result would not compile: %w", err)
	}
	return out, nil
}

// Remove drops a rule and the comments written above it.
//
// The comments go too, deliberately. They were written about this rule, and a
// paragraph explaining why somebody may reach production, left behind after the
// rule granting it is gone, is worse than no comment at all.
//
// Only a rule this package could have composed. That boundary is the point: the
// rules it does not recognise are the forbids and the administration tiers —
// the step-up requirement, the device-bound requirement for SSH, who may
// administer the directory. Those are the guardrails the composable rules sit
// inside, and a button that removes one of them with a click is not something
// this should offer. Editing the policy file and publishing it still does,
// which is the right amount of friction for changing a guardrail.
func Remove(document, id string) (string, error) {
	chunks, err := split(document)
	if err != nil {
		return "", err
	}

	var kept []string
	found := false
	for _, c := range chunks {
		if c.id == id {
			if _, ok := recognise(c.normalised); !ok {
				return "", fmt.Errorf(
					"policy: %q was written by hand — a forbid, or a rule with a "+
						"condition this cannot express. Remove it by publishing an "+
						"edited policy set, so the change is reviewed as text", id)
			}
			found = true
			continue
		}
		kept = append(kept, strings.TrimSpace(c.text))
	}
	if !found {
		return "", fmt.Errorf("policy: no rule called %q", id)
	}

	out := strings.Join(kept, "\n\n") + "\n"
	if _, err := NewEngine([]byte(out), 0); err != nil {
		return "", fmt.Errorf("policy: the result would not compile: %w", err)
	}
	return out, nil
}

// chunk is one rule and everything written above it.
type chunk struct {
	// text is verbatim: leading comments and blank lines, the rule, and its
	// terminating semicolon. Preserved byte for byte when the document is
	// rewritten around it.
	text string

	// normalised is text with comments removed and whitespace collapsed, which
	// is what the recogniser matches.
	normalised string

	id string
}

// split divides a document into one chunk per rule.
//
// A hand-rolled scanner rather than splitting on ";" because a semicolon inside
// a string literal is legal Cedar and would cut a rule in half — producing two
// fragments, neither of which parses, from a document that was fine. The same
// scan strips // comments, which is why it has to know about strings at all:
// "https://example.com" contains what looks exactly like a comment.
func split(document string) ([]chunk, error) {
	var (
		chunks    []chunk
		start     int
		normal    strings.Builder
		inString  bool
		inComment bool
		escaped   bool
	)

	flush := func(end int) {
		text := document[start:end]
		if strings.TrimSpace(text) == "" {
			return
		}
		c := chunk{
			text:       strings.TrimSpace(text),
			normalised: strings.Join(strings.Fields(normal.String()), " "),
		}
		if m := idPattern.FindStringSubmatch(c.normalised); m != nil {
			c.id = m[1]
		}
		chunks = append(chunks, c)
		normal.Reset()
		start = end
	}

	for i := 0; i < len(document); i++ {
		ch := document[i]

		switch {
		case inComment:
			if ch == '\n' {
				inComment = false
				normal.WriteByte(' ')
			}
			continue

		case inString:
			normal.WriteByte(ch)
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue

		case ch == '/' && i+1 < len(document) && document[i+1] == '/':
			inComment = true
			i++
			continue

		case ch == '"':
			inString = true
			normal.WriteByte(ch)
			continue

		case ch == ';':
			normal.WriteByte(ch)
			flush(i + 1)
			continue
		}

		normal.WriteByte(ch)
	}

	if inString {
		return nil, errors.New("policy: the document ends inside a string literal")
	}
	// Whatever follows the last semicolon: a trailing comment, or a rule
	// somebody forgot to terminate. Kept rather than dropped — losing a
	// half-written rule while tidying the file would be a poor trade.
	if strings.TrimSpace(document[start:]) != "" {
		flush(len(document))
	}
	return chunks, nil
}
