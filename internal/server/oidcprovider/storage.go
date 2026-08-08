package oidcprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"go.londer.be/cardinal/internal/server/claims"
	"go.londer.be/cardinal/internal/store"
)

// Storage implements op.Storage over the directory.
type Storage struct {
	store  *store.Store
	claims *claims.Resolver

	// sealKey decrypts the signing key. Held here rather than read per request
	// because it comes from configuration and never changes at runtime.
	sealKey string

	// loginURL is where an unauthenticated authorization request is sent.
	loginURL func(authRequestID string) string
}

// NewStorage adapts the directory to the op.Storage interface.
func NewStorage(s *store.Store, resolver *claims.Resolver, sealKey string, loginURL func(string) string) *Storage {
	return &Storage{store: s, claims: resolver, sealKey: sealKey, loginURL: loginURL}
}

// Health reports whether the database behind the provider is reachable.
func (s *Storage) Health(ctx context.Context) error { return s.store.Ping(ctx) }

// ── Clients ────────────────────────────────────────────────────────────────

// GetClientByClientID looks up a registered relying party.
func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	c, err := s.store.OIDCClientByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrClientNotFound) {
			return nil, oidc.ErrInvalidClient().WithDescription("unknown client")
		}
		return nil, err
	}
	return &client{c: c, loginURL: s.loginURL}, nil
}

// AuthorizeClientIDSecret verifies a confidential client's secret.
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, secret string) error {
	if err := s.store.VerifyClientSecret(ctx, clientID, secret); err != nil {
		// Deliberately identical for "no such client" and "wrong secret": the
		// distinction would let anyone enumerate registered clients.
		return oidc.ErrInvalidClient().WithDescription("client authentication failed")
	}
	return nil
}

// ── Authorization requests ─────────────────────────────────────────────────

// CreateAuthRequest records a new authorization request.
func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	// Scopes are narrowed to what the client is registered for, here, before
	// anything is recorded.
	//
	// The library cannot do this for us: it treats the standard OIDC scopes —
	// profile, email, offline_access — as always permissible and never consults
	// the client's IsScopeAllowed for them. That is defensible for a generic
	// library and wrong for Cardinal, because offline_access is what decides
	// whether a refresh token is issued. Without this, a client registered for
	// `openid profile` could ask for offline_access and walk away with a
	// long-lived credential nobody approved it for — and the client listing
	// would still show the narrow registration.
	scopes := s.permittedScopes(ctx, req.ClientID, req.Scopes)

	stored := &store.AuthRequest{
		ClientID:            req.ClientID,
		Scopes:              scopes,
		ResponseType:        string(req.ResponseType),
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),

		// Kept because they constrain how the user must authenticate, and the
		// decision belongs at completion time rather than here. Dropping them
		// let Cardinal answer "yes, they authenticated" to a client that had
		// asked for a fresh ceremony and never got one.
		Prompt: []string(req.Prompt),
	}
	if req.MaxAge != nil {
		// Clamped rather than converted. max_age arrives as an unbounded
		// unsigned integer and is compared as a time.Duration, which counts
		// nanoseconds in an int64 and so overflows past roughly 292 years — a
		// wrapped negative would turn "any age is acceptable" into "always
		// re-authenticate". Sixty-eight years is beyond any real policy and
		// well clear of the overflow.
		const ceiling = uint64(math.MaxInt32)
		maxAge := int64(math.MaxInt32)
		if uint64(*req.MaxAge) < ceiling {
			maxAge = int64(*req.MaxAge)
		}
		stored.MaxAge = &maxAge
	}

	if err := s.store.CreateAuthRequest(ctx, stored); err != nil {
		return nil, err
	}
	return &authRequest{r: stored}, nil
}

// permittedScopes intersects a request's scopes with the client's registration.
//
// `openid` is always kept: without it the request is not an OIDC request at
// all, and dropping it would produce a confusing failure far from the cause.
// An unknown client returns the requested scopes unchanged, because the
// library rejects the request on its own moments later and duplicating that
// judgement here would only add a second place for it to differ.
func (s *Storage) permittedScopes(ctx context.Context, clientID string, requested []string) []string {
	c, err := s.store.OIDCClientByID(ctx, clientID)
	if err != nil {
		return requested
	}

	allowed := make(map[string]struct{}, len(c.Scopes))
	for _, scope := range c.Scopes {
		allowed[scope] = struct{}{}
	}

	kept := make([]string, 0, len(requested))
	for _, scope := range requested {
		if scope == oidc.ScopeOpenID {
			kept = append(kept, scope)
			continue
		}
		if _, ok := allowed[scope]; ok {
			kept = append(kept, scope)
		}
	}
	return kept
}

// AuthRequestByID retrieves a pending authorization request.
func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("malformed request id")
	}

	stored, err := s.store.AuthRequestByID(ctx, parsed)
	if err != nil {
		return nil, oidc.ErrInvalidRequest().WithDescription("unknown or expired request")
	}
	return &authRequest{r: stored}, nil
}

// AuthRequestByCode exchanges an authorization code for its request.
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	// Redeeming consumes the code. The library calls this exactly once per
	// token exchange, and single use is enforced in the database rather than
	// relying on that (ADR 0004).
	stored, err := s.store.RedeemAuthCode(ctx, code)
	if err != nil {
		if errors.Is(err, store.ErrAuthCodeReplayed) {
			// A replayed code means either a buggy client or a stolen one, and
			// the second is worth noticing. The client is told nothing extra.
			return nil, oidc.ErrInvalidGrant().WithDescription("authorization code already used")
		}
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid authorization code")
	}
	return &authRequest{r: stored}, nil
}

// SaveAuthCode attaches an issued authorization code to its request.
func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("oidcprovider: malformed request id: %w", err)
	}
	return s.store.SaveAuthCode(ctx, parsed, code)
}

// DeleteAuthRequest discards a request once it is spent.
func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		// Nothing to delete. An id that is not a UUID matches no auth request,
		// so the caller's intent — that it be gone — already holds.
		return nil //nolint:nilerr // absence is the requested state
	}
	return s.store.DeleteAuthRequest(ctx, parsed)
}

// CompleteAuthentication records that a subject signed in for a request.
//
// Called by Cardinal's own login flow, not by the library: the library hands
// off to LoginURL and expects to be told when the user comes back.
func (s *Storage) CompleteAuthentication(ctx context.Context, requestID, subjectID uuid.UUID, session *store.Session) error {
	// amr describes what actually happened, in RFC 8176 terms, so a relying
	// party can make its own judgement rather than trusting that Cardinal's
	// policy matched its needs.
	amr := []string{}
	switch session.AuthMethod {
	case "passkey":
		amr = append(amr, "swk", "user") // software/hardware key, user present
		if session.DeviceBound {
			amr = append(amr, "hwk")
		}
	case "recovery_code":
		amr = append(amr, "rba")
	}

	return s.store.CompleteAuthRequest(ctx, requestID, subjectID, session.AuthAt, amr)
}

// ── Tokens ─────────────────────────────────────────────────────────────────

// CreateAccessToken issues an access token for a completed request.
func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	token, err := s.createToken(ctx, req, "")
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID.String(), token.ExpiresAt, nil
}

// CreateAccessAndRefreshTokens issues both, rotating any refresh token given.
func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	refresh, err := newOpaqueToken()
	if err != nil {
		return "", "", time.Time{}, err
	}

	token, err := s.createToken(ctx, req, refresh)
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Refresh token rotation: the old token dies as the new one is issued.
	//
	// Required by OAuth 2.1 for public clients, and worth doing for all of
	// them. A stolen refresh token is long-lived, so rotation both limits the
	// window and makes theft detectable — the legitimate client's next refresh
	// fails, which is a signal rather than silence.
	if currentRefreshToken != "" {
		if previous, err := s.store.TokenByRefresh(ctx, currentRefreshToken); err == nil {
			if err := s.store.RevokeToken(ctx, previous.ID); err != nil {
				return "", "", time.Time{}, err
			}
		}
	}

	return token.ID.String(), refresh, token.ExpiresAt, nil
}

func (s *Storage) createToken(ctx context.Context, req op.TokenRequest, refresh string) (*store.Token, error) {
	subjectID, err := uuid.Parse(req.GetSubject())
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: malformed subject: %w", err)
	}

	audience := req.GetAudience()
	clientID := ""
	if len(audience) > 0 {
		clientID = audience[0]
	}

	lifetime := 15 * time.Minute
	if c, err := s.store.OIDCClientByID(ctx, clientID); err == nil {
		lifetime = c.AccessTokenLifetime
	}

	token := &store.Token{
		ClientID:  clientID,
		SubjectID: subjectID,
		Scopes:    req.GetScopes(),
		Audience:  audience,
		AuthTime:  time.Now(),
		ExpiresAt: time.Now().Add(lifetime),
	}

	// Link to the browser session where one exists, so signing out revokes
	// these tokens rather than leaving them live for their full lifetime.
	if ar, ok := req.(*authRequest); ok {
		token.AuthTime = ar.r.AuthTime
		token.AMR = ar.r.AMR
	}

	if err := s.store.CreateToken(ctx, token, refresh); err != nil {
		return nil, err
	}
	return token, nil
}

// TokenRequestByRefreshToken resolves a refresh token to what it may renew.
func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	token, err := s.store.TokenByRefresh(ctx, refreshToken)
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid refresh token")
	}
	return &refreshRequest{t: token}, nil
}

// TerminateSession ends a subject's sessions on back-channel logout.
func (s *Storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	subjectID, err := uuid.Parse(userID)
	if err != nil {
		// Same reasoning as DeleteAuthRequest: sessions are keyed by UUID, so
		// an unparseable subject owns none and there is nothing to terminate.
		return nil //nolint:nilerr // absence is the requested state
	}
	_, err = s.store.RevokeAllSessions(ctx, subjectID, &subjectID)
	return err
}

// RevokeToken invalidates an access or refresh token.
func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *oidc.Error {
	// A refresh token arrives as the token itself; an access token as its ID.
	if token, err := s.store.TokenByRefresh(ctx, tokenOrTokenID); err == nil {
		if err := s.store.RevokeToken(ctx, token.ID); err != nil {
			return oidc.ErrServerError().WithDescription("could not revoke token")
		}
		return nil
	}

	if id, err := uuid.Parse(tokenOrTokenID); err == nil {
		if err := s.store.RevokeToken(ctx, id); err != nil {
			return oidc.ErrServerError().WithDescription("could not revoke token")
		}
	}

	// RFC 7009: revoking an unknown token is a success. Reporting otherwise
	// would let a caller probe which tokens exist.
	return nil
}

// GetRefreshTokenInfo resolves a refresh token to its subject and id.
func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	stored, err := s.store.TokenByRefresh(ctx, token)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return stored.SubjectID.String(), stored.ID.String(), nil
}

// ── Claims ─────────────────────────────────────────────────────────────────

// SetUserinfoFromScopes is deprecated in the library and intentionally empty.
// SetUserinfoFromRequest below is the live hook.
func (s *Storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}

// SetUserinfoFromRequest populates the ID token's claims.
//
// Required, not optional in practice: the library builds the ID token from the
// userinfo object it asks storage to fill, so without this the token ships
// without a `sub` claim — which is mandatory, and which most client libraries
// reject only at the point a user tries to sign in.
//
// The deprecated SetUserinfoFromScopes is the one the interface forces you to
// declare, so it is easy to implement that, see tokens being issued, and never
// notice the ID token is malformed.
func (s *Storage) SetUserinfoFromRequest(ctx context.Context, info *oidc.UserInfo, request op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, info, request.GetSubject(), scopes)
}

// SetUserinfoFromToken fills the userinfo response for a token.
func (s *Storage) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, tokenID, subject, _ string) error {
	return s.setUserinfo(ctx, info, subject, []string{
		oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, "groups",
	})
}

// SetIntrospectionFromToken fills an introspection response.
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, info *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	userinfo := new(oidc.UserInfo)
	if err := s.setUserinfo(ctx, userinfo, subject, []string{
		oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, "groups",
	}); err != nil {
		return err
	}
	info.SetUserInfo(userinfo)
	return nil
}

// setUserinfo populates claims from the shared projection.
//
// The same resolution that feeds forwardAuth headers, SCIM attributes and SSH
// certificate principals. Groups are resolved with expiry already applied, so
// an expired grant simply is not in the list and cannot leak into a token.
func (s *Storage) setUserinfo(ctx context.Context, info *oidc.UserInfo, subject string, scopes []string) error {
	subjectID, err := uuid.Parse(subject)
	if err != nil {
		return fmt.Errorf("oidcprovider: malformed subject: %w", err)
	}

	resolved, err := s.claims.ResolveByID(ctx, subjectID)
	if err != nil {
		return err
	}

	info.Subject = resolved.ID.String()

	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeProfile:
			info.PreferredUsername = resolved.Login
			info.Name = resolved.DisplayName
			if info.Name == "" {
				info.Name = resolved.Login
			}

		case oidc.ScopeEmail:
			// Email lives in the schema-governed attributes rather than a
			// column, because not every entity type has one and Cardinal does
			// not require it.
			if email, ok := resolved.Attrs["email"].(string); ok && email != "" {
				info.Email = email
				// Deliberately not asserting verification Cardinal has not
				// performed: a relying party that trusts email_verified for
				// account linking would be trusting a claim we invented.
				info.EmailVerified = false
			}

		case "groups":
			info.AppendClaims("groups", resolved.GroupNames())
			// Stable identifiers beside the names. A relying party deciding
			// what somebody may do should key on these: a group's name is a
			// mutable attribute (ADR 0002), so permission logic written against
			// the string breaks silently the day someone renames it.
			info.AppendClaims("group_ids", resolved.GroupIDs())
		}
	}

	return nil
}

// GetPrivateClaimsFromScopes projects directory attributes into claims.
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	subjectID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: malformed subject: %w", err)
	}

	resolved, err := s.claims.ResolveByID(ctx, subjectID)
	if err != nil {
		return nil, err
	}

	private := map[string]any{}
	for _, scope := range scopes {
		if scope == "groups" {
			private["groups"] = resolved.GroupNames()
			private["group_ids"] = resolved.GroupIDs()
		}
	}
	return private, nil
}

// ValidateJWTProfileScopes is used by the JWT profile grant, which Cardinal
// does not enable. Returning the requested scopes unchanged is harmless because
// no client can reach this path.
func (s *Storage) ValidateJWTProfileScopes(_ context.Context, _ string, scopes []string) ([]string, error) {
	return scopes, nil
}

// GetKeyByIDAndClientID returns a client's public key for private_key_jwt.
func (s *Storage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, oidc.ErrInvalidClient().WithDescription(
		"private_key_jwt client authentication is not yet available")
}

// ── Signing keys ───────────────────────────────────────────────────────────

// SigningKey returns the key currently used to sign tokens.
func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	key, err := s.store.ActiveSigningKey(ctx, s.sealKey)
	if err != nil {
		return nil, err
	}
	return &signingKey{key: key}, nil
}

// SignatureAlgorithms lists what this provider will sign with.
func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet serves the JWKS.
//
// Includes retired keys until they expire, so tokens signed moments before a
// rotation still verify. Omitting them is how key rotation becomes an outage.
func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	keys, err := s.store.VerificationKeys(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]op.Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, &publicKey{key: k})
	}
	return out, nil
}

// ── helpers ────────────────────────────────────────────────────────────────

// refreshRequest adapts a stored token to op.RefreshTokenRequest.
type refreshRequest struct {
	t *store.Token
}

// GetAMR lists how the subject authenticated.
func (r *refreshRequest) GetAMR() []string { return r.t.AMR }

// GetAudience is the client itself; Cardinal issues no cross-client audiences.
func (r *refreshRequest) GetAudience() []string { return r.t.Audience }

// GetAuthTime is when the subject actually authenticated, which drives
// max_age and step-up decisions.
func (r *refreshRequest) GetAuthTime() time.Time { return r.t.AuthTime }

// GetClientID returns the client this request belongs to.
func (r *refreshRequest) GetClientID() string { return r.t.ClientID }

// GetScopes lists the scopes requested.
func (r *refreshRequest) GetScopes() []string { return r.t.Scopes }

// GetSubject returns the authenticated subject, empty until it has one.
func (r *refreshRequest) GetSubject() string { return r.t.SubjectID.String() }

// SetCurrentScopes narrows the scopes carried by a refreshed token.
func (r *refreshRequest) SetCurrentScopes(scopes []string) {
	r.t.Scopes = scopes
}

func newOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oidcprovider: generating token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
