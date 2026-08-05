package oidcprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/claims"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
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

func NewStorage(s *store.Store, resolver *claims.Resolver, sealKey string, loginURL func(string) string) *Storage {
	return &Storage{store: s, claims: resolver, sealKey: sealKey, loginURL: loginURL}
}

func (s *Storage) Health(ctx context.Context) error { return s.store.Ping(ctx) }

// ── Clients ────────────────────────────────────────────────────────────────

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

func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, secret string) error {
	if err := s.store.VerifyClientSecret(ctx, clientID, secret); err != nil {
		// Deliberately identical for "no such client" and "wrong secret": the
		// distinction would let anyone enumerate registered clients.
		return oidc.ErrInvalidClient().WithDescription("client authentication failed")
	}
	return nil
}

// ── Authorization requests ─────────────────────────────────────────────────

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	stored := &store.AuthRequest{
		ClientID:            req.ClientID,
		Scopes:              req.Scopes,
		ResponseType:        string(req.ResponseType),
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),
	}

	if err := s.store.CreateAuthRequest(ctx, stored); err != nil {
		return nil, err
	}
	return &authRequest{r: stored}, nil
}

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

func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("oidcprovider: malformed request id: %w", err)
	}
	return s.store.SaveAuthCode(ctx, parsed, code)
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil // Nothing to delete; not worth an error.
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
	case "break_glass":
		// Deliberately visible. A relying party may reasonably refuse an
		// emergency session for a sensitive operation, and it can only do that
		// if we say so.
		amr = append(amr, "break_glass")
	case "recovery_code":
		amr = append(amr, "rba")
	}

	return s.store.CompleteAuthRequest(ctx, requestID, subjectID, session.AuthAt, amr)
}

// ── Tokens ─────────────────────────────────────────────────────────────────

func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	token, err := s.createToken(ctx, req, "")
	if err != nil {
		return "", time.Time{}, err
	}
	return token.ID.String(), token.ExpiresAt, nil
}

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

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	token, err := s.store.TokenByRefresh(ctx, refreshToken)
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid refresh token")
	}
	return &refreshRequest{t: token}, nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	subjectID, err := uuid.Parse(userID)
	if err != nil {
		return nil
	}
	_, err = s.store.RevokeAllSessions(ctx, subjectID, &subjectID)
	return err
}

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

func (s *Storage) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, tokenID, subject, _ string) error {
	return s.setUserinfo(ctx, info, subject, []string{
		oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, "groups",
	})
}

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
		}
	}

	return nil
}

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

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	key, err := s.store.ActiveSigningKey(ctx, s.sealKey)
	if err != nil {
		return nil, err
	}
	return &signingKey{key: key}, nil
}

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

func (r *refreshRequest) GetAMR() []string       { return r.t.AMR }
func (r *refreshRequest) GetAudience() []string  { return r.t.Audience }
func (r *refreshRequest) GetAuthTime() time.Time { return r.t.AuthTime }
func (r *refreshRequest) GetClientID() string    { return r.t.ClientID }
func (r *refreshRequest) GetScopes() []string    { return r.t.Scopes }
func (r *refreshRequest) GetSubject() string     { return r.t.SubjectID.String() }
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
