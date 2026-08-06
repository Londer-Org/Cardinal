// Package oidcprovider adapts Cardinal's directory to zitadel/oidc.
//
// The library owns protocol correctness — it is OpenID Foundation certified,
// which is not something worth reimplementing. This package supplies identity:
// which clients exist, who a subject is, and what claims they carry.
//
// Claims come from internal/claims, the same projection that feeds forwardAuth,
// SCIM and SSH certificate issuance (ADR 0007). Four surfaces cannot drift into
// disagreeing about who someone is, which in an authorization system is not a
// cosmetic concern.
package oidcprovider

import (
	"crypto/rsa"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// ── Client ─────────────────────────────────────────────────────────────────

// client adapts a registered relying party to op.Client.
type client struct {
	c        *store.OIDCClient
	loginURL func(authRequestID string) string
}

func (c *client) GetID() string          { return c.c.ClientID }
func (c *client) RedirectURIs() []string { return c.c.RedirectURIs }
func (c *client) PostLogoutRedirectURIs() []string {
	return c.c.PostLogoutRedirectURIs
}
func (c *client) LoginURL(id string) string { return c.loginURL(id) }
func (c *client) DevMode() bool             { return c.c.DevMode }
func (c *client) ClockSkew() time.Duration  { return 0 }

func (c *client) ApplicationType() op.ApplicationType {
	// Native applications get loopback redirect URIs and cannot hold a secret;
	// the distinction matters to the library's redirect validation.
	if c.c.Public() {
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}

func (c *client) AuthMethod() oidc.AuthMethod {
	switch c.c.AuthMethod {
	case store.AuthClientSecretBasic:
		return oidc.AuthMethodBasic
	case store.AuthClientSecretPost:
		return oidc.AuthMethodPost
	case store.AuthPrivateKeyJWT:
		return oidc.AuthMethodPrivateKeyJWT
	case store.AuthNone:
		return oidc.AuthMethodNone
	default:
		// Unknown means misconfigured, and the safest reading of a
		// misconfigured client is the one that demands the most.
		return oidc.AuthMethodBasic
	}
}

// ResponseTypes deliberately offers only `code`.
//
// The implicit and hybrid flows return tokens in the URL fragment, where they
// land in browser history and referrer headers. OAuth 2.1 removes them, and
// offering them here would let a client opt into a weaker flow than Cardinal
// otherwise guarantees.
func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *client) GrantTypes() []oidc.GrantType {
	grants := make([]oidc.GrantType, 0, len(c.c.GrantTypes))
	for _, g := range c.c.GrantTypes {
		grants = append(grants, oidc.GrantType(g))
	}
	return grants
}

// AccessTokenType is JWT so a resource server can validate a token against the
// JWKS without calling Cardinal on every request — which is what keeps an
// outage from taking every downstream API with it.
func (c *client) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }

func (c *client) IDTokenLifetime() time.Duration { return c.c.IDTokenLifetime }

// IDTokenUserinfoClaimsAssertion returns true: the ID token carries the claims
// the granted scopes asked for.
//
// This used to return false, with a comment about keeping the ID token small
// because it can travel in URLs. The reasoning was sound and the behaviour did
// not follow it: `groups` reached the ID token anyway, via private claims, so
// the token carried the one claim large enough to blow a header limit and
// omitted the small ones. An application asking for `profile` got a token with
// no name and no preferred_username in it, which is not a smaller token so much
// as a less useful one.
//
// Every mainstream provider — Keycloak, Google, Entra — puts profile claims in
// the ID token, and a great many relying parties read them from there and never
// call userinfo. Omitting them means those integrations silently show blank
// usernames, which is exactly how this was found.
//
// If token size ever becomes a real constraint, the fix is a per-client flag
// like the ones registration already has, not a global default that surprises
// every client.
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return true }

func (c *client) IsScopeAllowed(scope string) bool {
	for _, allowed := range c.c.Scopes {
		if scope == allowed {
			return true
		}
	}
	return false
}

// RestrictAdditionalIdTokenScopes and its access-token twin drop anything the
// client is not registered for. A client asking for a scope it was never
// granted gets silence rather than an error, per the spec's guidance.
func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return c.restrictScopes
}

func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return c.restrictScopes
}

func (c *client) restrictScopes(scopes []string) []string {
	kept := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if c.IsScopeAllowed(scope) {
			kept = append(kept, scope)
		}
	}
	return kept
}

// ── AuthRequest ────────────────────────────────────────────────────────────

// authRequest adapts an in-flight authorization to op.AuthRequest.
type authRequest struct {
	r *store.AuthRequest
}

func (a *authRequest) GetID() string          { return a.r.ID.String() }
func (a *authRequest) GetClientID() string    { return a.r.ClientID }
func (a *authRequest) GetRedirectURI() string { return a.r.RedirectURI }
func (a *authRequest) GetState() string       { return a.r.State }
func (a *authRequest) GetNonce() string       { return a.r.Nonce }
func (a *authRequest) GetScopes() []string    { return a.r.Scopes }
func (a *authRequest) GetAuthTime() time.Time { return a.r.AuthTime }
func (a *authRequest) Done() bool             { return a.r.Done }

func (a *authRequest) GetSubject() string {
	if a.r.SubjectID == nil {
		return ""
	}
	// The immutable UUID, never the login. The `sub` claim must be stable for
	// the life of the account: a relying party keys its own records on it, so a
	// value that changed when someone was renamed would silently orphan their
	// data (ADR 0002).
	return a.r.SubjectID.String()
}

// GetACR reports the authentication context.
//
// Left empty rather than invented: an ACR value implies a published policy
// about what it means, and asserting one Cardinal has not defined would be
// worse than asserting nothing. Relying parties needing assurance should read
// `amr` instead, which describes what actually happened.
func (a *authRequest) GetACR() string { return "" }

// GetAMR reports how the subject authenticated, in RFC 8176 terms.
//
// This is what lets a relying party make its own decision — refusing a
// break-glass session for a sensitive operation, say — rather than trusting
// that Cardinal's policy matched its own needs.
func (a *authRequest) GetAMR() []string { return a.r.AMR }

func (a *authRequest) GetAudience() []string { return []string{a.r.ClientID} }

func (a *authRequest) GetResponseType() oidc.ResponseType {
	return oidc.ResponseType(a.r.ResponseType)
}

// GetResponseMode returns empty, letting the library apply the default for the
// response type — `query` for the code flow.
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return "" }

func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.r.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.r.CodeChallenge,
		Method:    oidc.CodeChallengeMethod(a.r.CodeChallengeMethod),
	}
}

// SubjectUUID parses the subject back out, for storage calls.
func (a *authRequest) SubjectUUID() (uuid.UUID, bool) {
	if a.r.SubjectID == nil {
		return uuid.Nil, false
	}
	return *a.r.SubjectID, true
}

// ── Keys ───────────────────────────────────────────────────────────────────

// signingKey adapts a Cardinal signing key to op.SigningKey.
type signingKey struct {
	key *store.SigningKey
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return jose.RS256
}
func (k *signingKey) Key() any   { return k.key.Private }
func (k *signingKey) ID() string { return k.key.KeyID }

// publicKey adapts a verification key to op.Key, for the JWKS endpoint.
type publicKey struct {
	key *store.SigningKey
}

func (k *publicKey) ID() string                         { return k.key.KeyID }
func (k *publicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *publicKey) Use() string                        { return "sig" }
func (k *publicKey) Key() any {
	pub, ok := k.key.Private.Public().(*rsa.PublicKey)
	if !ok {
		return nil
	}
	return pub
}
