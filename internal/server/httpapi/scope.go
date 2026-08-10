package httpapi

import (
	"net/http"
	"slices"

	"go.londer.be/cardinal/internal/store"
)

// What an access token is allowed to attempt.
//
// A token authenticates its owner and is never device-bound, so policy already
// refuses it every administrative action and every SSH certificate (ADR 0018).
// What it does not refuse is everything else the owner can do without a
// hardware key, and that is a wider set than the ADR's framing suggests: the
// decision log, the active policy set, the owner's own profile, and every
// application the owner can reach. For a credential living in a CI variable
// that is a grant nobody would write down on purpose.
//
// A scope is a ceiling. It cannot widen anything — policy still decides, and a
// token still cannot exceed its owner — so this is not a second authorization
// system running alongside Cedar. It is the answer to a question Cedar cannot
// ask, because Cedar sees a principal and not the credential that presented it:
// "was this token issued for this?"
//
// The vocabulary is deliberately small and closed. Scopes that describe
// endpoints multiply with the API and end up meaning nothing; these describe
// the four things a token is actually ever wanted for, plus knowing who it is.

// Scopes an access token may hold.
const (
	// ScopeIdentity reads who the token belongs to. Almost every client needs
	// it, and it is the one scope that reveals nothing the holder did not
	// already have — they are holding the credential.
	ScopeIdentity = "identity"

	// ScopeApplications reaches applications through the proxy. The reason
	// tokens exist: a script calling an internal service behind forwardAuth.
	ScopeApplications = "applications"

	// ScopeProfile edits the owner's display name and email. Separate from
	// identity, and rarely wanted: a pipeline that can rename its owner is a
	// pipeline that can make an audit trail read differently.
	ScopeProfile = "profile"

	// ScopeDecisions reads the decision log — who was refused what, and by
	// which rule. Useful to a monitoring job and a map of the organisation to
	// anybody else.
	ScopeDecisions = "decisions"

	// ScopePolicy reads the active policy set. Useful to a CI job checking a
	// deployment matches git; it is also every rule governing every door.
	ScopePolicy = "policy"

	// ScopeSCIM provisions accounts, for an identity provider.
	//
	// The one scope that writes to the directory, and the reason it is a scope
	// at all: a token that could provision because its owner happens to be a
	// provisioner would make every other token that person holds a provisioning
	// credential too. Both must be true — this scope, and policy permitting
	// Provision (ADR 0031).
	ScopeSCIM = "scim"

	// ScopeEvents collects the security events queued for a receiver.
	//
	// The only scope whose holder is normally an application rather than a
	// person: a poll stream (RFC 8936) has the receiver connect to Cardinal, so
	// the receiver needs a credential of its own. It reads nothing but the
	// events already addressed to it — each one a token signed for its audience
	// and already destined for its stream — so this widens nothing that push
	// delivery did not already send unasked.
	ScopeEvents = "events"
)

// AllScopes is the closed vocabulary, in the order a listing should show it.
var AllScopes = []string{
	ScopeIdentity, ScopeApplications, ScopeProfile, ScopeDecisions, ScopePolicy,
	ScopeSCIM, ScopeEvents,
}

// ValidScope reports whether a name is one Cardinal knows.
//
// Checked at issue time rather than at use time. A token issued with a
// misspelled scope would authenticate and then be refused everything, and the
// refusal arrives wherever the token is used — usually an unattended pipeline,
// hours later, with a message about permissions rather than about spelling.
func ValidScope(name string) bool { return slices.Contains(AllScopes, name) }

// requireScope refuses a token that was not issued for this.
//
// A no-op for a passkey session, which is the whole point of the design: a
// person at a browser holds no scopes and is bounded by policy alone. Scopes
// exist because a token is a credential somebody left somewhere, and the
// question "what did I create this for" has no other place to live.
func (s *Server) requireScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := SessionFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		if session.AuthMethod != store.AuthMethodAccessToken {
			next.ServeHTTP(w, r)
			return
		}

		if !slices.Contains(session.Scopes, scope) {
			// Named, and the remedy given. The alternative is a 403 in a
			// pipeline log at 3am that reads as "this account lost access",
			// which sends somebody to the directory rather than to the token.
			writeError(w, http.StatusForbidden,
				"this access token was not issued with the "+scope+" scope. "+
					"Scopes cannot be changed on an existing token — issue a new "+
					"one with `"+issueCommandFor(scope)+"`")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// issueCommandFor is the command that produces a token carrying this scope.
//
// Not one sentence with the scope substituted in, because for one scope that
// sentence is wrong. `events` belongs to a receiver rather than a person, and
// `cardinal token create <login> -scope events` takes a login — so the generic
// advice told whoever hit this to run a command that cannot be run, for a
// principal that is not a person. Observed against the running stack.
func issueCommandFor(scope string) string {
	if scope == ScopeEvents {
		return "cardinal ssf token <application>"
	}
	return "cardinal token create <login> -scope " + scope
}
