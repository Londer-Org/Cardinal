package oidcprovider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/claims"
	"github.com/arthur-lonfils/cardinal/internal/config"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Storage must satisfy the library's contract. Asserted at compile time so a
// missing method is a build failure rather than a nil-interface panic on the
// first authorization request.
var _ op.Storage = (*Storage)(nil)

// Provider is Cardinal's OpenID Connect provider.
type Provider struct {
	provider *op.Provider
	storage  *Storage
}

// New builds the provider.
//
// The signing key is created on first use rather than requiring a separate
// bootstrap step: a deployment that starts without one would otherwise fail
// every authorization with an error nobody could act on.
func New(ctx context.Context, s *store.Store, resolver *claims.Resolver, cfg *config.Config) (*Provider, error) {
	if cfg.OIDC.SigningKeyEncryptionKey == "" {
		return nil, fmt.Errorf(
			"oidcprovider: oidc.signing_key_encryption_key is required — the " +
				"signing key can forge tokens for every application, so it is not " +
				"stored in the clear")
	}

	if _, err := s.EnsureSigningKey(ctx, cfg.OIDC.SigningKeyEncryptionKey); err != nil {
		return nil, fmt.Errorf("oidcprovider: preparing signing key: %w", err)
	}

	issuer := cfg.Server.PublicURL
	if issuer == "" {
		return nil, fmt.Errorf(
			"oidcprovider: server.public_url is required — it is the issuer " +
				"identifier, and every token carries it")
	}

	storage := NewStorage(s, resolver, cfg.OIDC.SigningKeyEncryptionKey,
		func(authRequestID string) string {
			// Where the library sends an unauthenticated authorization request.
			// Cardinal's own login page picks the ID back up and completes the
			// flow once the user has signed in.
			return "/oidc/login?auth=" + authRequestID
		})

	// The key that encrypts the library's internal cookies. Derived from the
	// same configured secret so there is one thing to manage, but hashed with a
	// distinct label so the two uses cannot be substituted for one another.
	cookieKey := sha256.Sum256([]byte("cardinal-oidc-cookie:" + cfg.OIDC.SigningKeyEncryptionKey))

	provider, err := op.NewProvider(&op.Config{
		CryptoKey: cookieKey,

		// Refresh tokens are enabled; the storage rotates them on every use.
		SupportedUILocales: nil,

		// PKCE is advertised as supported, and every registered client requires
		// it (OAuth 2.1). Advertising S256 only: `plain` lets anyone who
		// intercepted the challenge derive the verifier, which defeats the
		// point.
		CodeMethodS256: true,

		// Authentication at the token endpoint may use a client secret or none
		// (public clients with PKCE).
		AuthMethodPost:          true,
		AuthMethodPrivateKeyJWT: false,
		GrantTypeRefreshToken:   true,
		RequestObjectSupported:  false,
		SupportedClaims:         op.DefaultSupportedClaims,
		DeviceAuthorization:     op.DeviceAuthorizationConfig{Lifetime: 0},
	}, storage, op.StaticIssuer(issuer),
		// Endpoints are stated explicitly rather than left to defaults.
		//
		// Two reasons. Everything lives under /oidc/ so it cannot collide with
		// the admin UI's client-side routes as those grow. And stating them
		// here is what guarantees the discovery document and the actual routing
		// agree — the default set advertised /revoke while Cardinal mounted
		// /oauth/revoke, which a client would only discover at revocation time.
		op.WithCustomEndpoints(
			op.NewEndpoint("/oidc/authorize"),
			op.NewEndpoint("/oidc/token"),
			op.NewEndpoint("/oidc/userinfo"),
			op.NewEndpoint("/oidc/revoke"),
			op.NewEndpoint("/oidc/end-session"),
			op.NewEndpoint("/oidc/keys"),
		),
		op.WithCustomIntrospectionEndpoint(op.NewEndpoint("/oidc/introspect")),

		// Cardinal terminates TLS at the proxy, so the library must not insist
		// on seeing HTTPS itself. The proxy is what guarantees it.
		op.WithAllowInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: building provider: %w", err)
	}

	return &Provider{provider: provider, storage: storage}, nil
}

// Handler serves the OIDC endpoints: authorize, token, userinfo and JWKS.
//
// Discovery is served by DiscoveryHandler instead — see there for why.
func (p *Provider) Handler() http.Handler { return p.provider }

// DiscoveryHandler serves /.well-known/openid-configuration.
//
// Cardinal's own, rather than the library's, because the library's answer is
// not about Cardinal. `ResponseTypes` is a hardcoded list carrying the comment
// "TODO: ok for now, check later if dynamic needed", `GrantTypes` always
// includes implicit, and `GrantTypeJWTAuthorizationSupported` is a method whose
// entire body is `return true`. None of it consults the configuration, so the
// document advertised the implicit flow, `id_token token`, a JWT-bearer grant
// and a device authorization endpoint — four things no client here can use, and
// the device endpoint answered with Cardinal's CSRF error rather than anything
// resembling OAuth.
//
// That is worse than untidy. Discovery is a contract: a relying party reads it
// to decide which flow to run, and a conformance suite reads it to decide which
// tests to run. Advertising a flow that every registered client refuses means
// the first honest reader of the document is the one who finds out.
//
// Everything else is still derived from the library, so endpoints, claims and
// signing algorithms cannot drift from what is actually mounted. Only the
// fields it will not compute are overridden.
func (p *Provider) DiscoveryHandler() http.Handler {
	// Wrapped in the library's issuer interceptor, which is what puts the
	// issuer into the request context. Every endpoint in the document is
	// rendered as `.Absolute(issuer)`, so without it they all come out as bare
	// paths — /oidc/token rather than https://host/oidc/token — and a relying
	// party has nothing to resolve them against. The provider applies this to
	// its own handlers; registering one on the mux directly bypasses it.
	issuer := op.NewIssuerInterceptor(p.provider.IssuerFromRequest)

	return issuer.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := op.CreateDiscoveryConfig(r.Context(), p.provider, p.storage)

		// Authorization code only, and PKCE is required for every client
		// (OAuth 2.1). The implicit flow returns tokens in a URL fragment,
		// which lands them in browser history and referrers.
		cfg.ResponseTypesSupported = []string{string(oidc.ResponseTypeCode)}
		cfg.GrantTypesSupported = []oidc.GrantType{
			oidc.GrantTypeCode,
			oidc.GrantTypeRefreshToken,
		}

		// Not implemented. Advertising the endpoint made a client's first
		// discovery of that fact a CSRF error on a POST.
		cfg.DeviceAuthorizationEndpoint = ""

		// The library's default scope list is openid/profile/email/phone/
		// address/offline_access regardless of what the provider can answer.
		// Cardinal holds no telephone number and no postal address, so those
		// two scopes were an invitation to ask for nothing — and `groups`,
		// which it does implement and which is the whole point of a directory
		// as an identity provider, was missing.
		cfg.ScopesSupported = []string{
			oidc.ScopeOpenID,
			oidc.ScopeProfile,
			oidc.ScopeEmail,
			oidc.ScopeOfflineAccess,
			"groups",
		}

		// Likewise the claims. This is the set Cardinal can actually put in a
		// token, rather than the union of everything the specification defines.
		cfg.ClaimsSupported = []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
			"azp", "at_hash", "c_hash",
			"name", "preferred_username",
			// Always false: Cardinal performs no verification, and a relying
			// party linking accounts on a claim we invented would be trusting
			// nothing.
			"email", "email_verified",
			"groups",
		}

		op.Discover(w, cfg)
	}))
}

// Storage exposes the storage layer, so Cardinal's login flow can complete an
// authorization request once the user has signed in.
func (p *Provider) Storage() *Storage { return p.storage }

// RotateSigningKey generates a new signing key, retiring the current one after
// a grace period during which it still verifies.
func (p *Provider) RotateSigningKey(ctx context.Context, s *store.Store, sealKey string) error {
	// The grace period must comfortably exceed the longest token lifetime, or
	// tokens issued moments before the rotation stop verifying.
	_, err := s.RotateSigningKey(ctx, sealKey, 48*time.Hour)
	return err
}
