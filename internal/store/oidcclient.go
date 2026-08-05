package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/event"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

var (
	ErrClientNotFound = errors.New("store: OIDC client not found")
	ErrInvalidSecret  = errors.New("store: client secret does not match")

	// ErrInsecureRedirect means a redirect URI would weaken the flow.
	ErrInsecureRedirect = errors.New("store: insecure redirect URI")
)

// AuthMethod is how a client authenticates at the token endpoint.
type AuthMethod string

const (
	// AuthNone is a public client — a single-page app or a mobile app. It holds
	// no secret because it cannot keep one, and relies on PKCE instead.
	AuthNone AuthMethod = "none"

	AuthClientSecretBasic AuthMethod = "client_secret_basic"
	AuthClientSecretPost  AuthMethod = "client_secret_post"

	// AuthPrivateKeyJWT is the strongest: the client signs an assertion with a
	// private key Cardinal never holds, so there is no shared secret to leak
	// from either side.
	AuthPrivateKeyJWT AuthMethod = "private_key_jwt"
)

// OIDCClient is a registered relying party.
type OIDCClient struct {
	EntityID uuid.UUID
	ClientID string
	Name     string

	AuthMethod AuthMethod
	secretHash []byte

	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	GrantTypes             []string
	Scopes                 []string

	RequirePKCE bool
	DevMode     bool

	AccessTokenLifetime  time.Duration
	IDTokenLifetime      time.Duration
	RefreshTokenLifetime time.Duration
}

// Public reports whether this client can keep a secret.
func (c *OIDCClient) Public() bool { return c.AuthMethod == AuthNone }

// RegisterClientInput describes a new relying party.
type RegisterClientInput struct {
	Name         string
	DisplayName  string
	AuthMethod   AuthMethod
	RedirectURIs []string
	Scopes       []string
	DevMode      bool
}

// RegisteredClient is returned once, at registration.
type RegisteredClient struct {
	Client *OIDCClient

	// Secret is shown once and never recoverable, for the same reason a
	// recovery code is: only its hash is stored.
	Secret string
}

// RegisterOIDCClient creates an application entity and its client registration.
//
// checkRelyingParty is called with each redirect URI's host before anything is
// written. It is how the recovery-email circularity rule from ADR 0009 is
// actually enforced: Cardinal refuses to become the identity provider for a
// domain it also trusts to recover accounts, because an outage would then take
// the recovery channel with it.
func (s *Store) RegisterOIDCClient(
	ctx context.Context,
	in RegisterClientInput,
	checkRelyingParty func(domain string) error,
	actorID *uuid.UUID,
) (*RegisteredClient, error) {
	if len(in.RedirectURIs) == 0 {
		return nil, fmt.Errorf("store: at least one redirect URI is required")
	}

	for _, raw := range in.RedirectURIs {
		u, err := validateRedirectURI(raw, in.DevMode)
		if err != nil {
			return nil, err
		}
		if checkRelyingParty != nil {
			if err := checkRelyingParty(u.Hostname()); err != nil {
				return nil, err
			}
		}
	}

	entity, err := directory.NewEntity(directory.TypeApplication, in.Name, in.DisplayName)
	if err != nil {
		return nil, err
	}

	clientID, err := newOpaqueID()
	if err != nil {
		return nil, err
	}

	out := &RegisteredClient{Client: &OIDCClient{
		EntityID:     entity.ID,
		ClientID:     clientID,
		Name:         in.Name,
		AuthMethod:   in.AuthMethod,
		RedirectURIs: in.RedirectURIs,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       in.Scopes,
		RequirePKCE:  true,
		DevMode:      in.DevMode,
	}}
	if len(out.Client.Scopes) == 0 {
		out.Client.Scopes = []string{"openid", "profile", "email", "groups"}
	}

	var secretHash []byte
	if in.AuthMethod == AuthClientSecretBasic || in.AuthMethod == AuthClientSecretPost {
		secret, err := newOpaqueID()
		if err != nil {
			return nil, err
		}
		out.Secret = secret
		secretHash = hashClientSecret(clientID, secret)
	}

	err = s.InTx(ctx, func(tx pgx.Tx) error {
		if err := insertEntityTx(ctx, tx, entity); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO oidc_clients
				(entity_id, client_id, secret_hash, auth_method, redirect_uris,
				 grant_types, scopes, require_pkce, dev_mode)
			VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8)`,
			entity.ID, clientID, secretHash, string(in.AuthMethod),
			in.RedirectURIs, out.Client.GrantTypes, out.Client.Scopes, in.DevMode,
		); err != nil {
			return fmt.Errorf("store: registering client: %w", err)
		}

		ev, err := event.New(event.ActionEntityCreated, &entity.ID, actorID,
			map[string]any{"type": string(directory.TypeApplication)})
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// validateRedirectURI rejects URIs that would weaken the flow.
//
// Redirect URIs are the single most abused part of OAuth: an attacker who can
// get a code delivered to a URI they control has the account. The checks here
// are the ones that matter in practice.
func validateRedirectURI(raw string, devMode bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %q is not a URL", ErrInsecureRedirect, raw)
	}

	switch {
	case u.Scheme == "":
		return nil, fmt.Errorf("%w: %q has no scheme", ErrInsecureRedirect, raw)

	case u.Fragment != "":
		// A fragment is never sent to the server and would be silently dropped,
		// so its presence means the author misunderstands the flow.
		return nil, fmt.Errorf("%w: %q must not contain a fragment",
			ErrInsecureRedirect, raw)

	case strings.Contains(raw, "*"):
		// Wildcards let an attacker who controls any matching host receive
		// authorization codes. No OAuth 2.1 implementation should accept them.
		return nil, fmt.Errorf("%w: %q contains a wildcard; redirect URIs must "+
			"match exactly", ErrInsecureRedirect, raw)

	case u.Scheme == "http":
		// Loopback stays permitted regardless: RFC 8252 requires it for native
		// apps, and the port varies per launch so it cannot be pinned.
		if isLoopback(u.Hostname()) {
			return u, nil
		}
		if !devMode {
			return nil, fmt.Errorf(
				"%w: %q uses http, so an authorization code would cross the "+
					"network in the clear; use https, or set dev_mode deliberately",
				ErrInsecureRedirect, raw)
		}
	}

	return u, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		strings.HasSuffix(host, ".localhost")
}

// OIDCClientByID loads a client for a request.
func (s *Store) OIDCClientByID(ctx context.Context, clientID string) (*OIDCClient, error) {
	var (
		c          OIDCClient
		authMethod string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT c.entity_id, c.client_id, e.name, c.secret_hash, c.auth_method,
		       c.redirect_uris, c.post_logout_redirect_uris, c.grant_types,
		       c.scopes, c.require_pkce, c.dev_mode,
		       c.access_token_lifetime, c.id_token_lifetime, c.refresh_token_lifetime
		  FROM oidc_clients c
		  JOIN entities e ON e.id = c.entity_id
		 WHERE c.client_id = $1 AND e.disabled_at IS NULL`,
		clientID,
	).Scan(&c.EntityID, &c.ClientID, &c.Name, &c.secretHash, &authMethod,
		&c.RedirectURIs, &c.PostLogoutRedirectURIs, &c.GrantTypes,
		&c.Scopes, &c.RequirePKCE, &c.DevMode,
		&c.AccessTokenLifetime, &c.IDTokenLifetime, &c.RefreshTokenLifetime)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClientNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: loading client: %w", err)
	}
	c.AuthMethod = AuthMethod(authMethod)
	return &c, nil
}

// VerifyClientSecret checks a secret in constant time.
func (s *Store) VerifyClientSecret(ctx context.Context, clientID, secret string) error {
	client, err := s.OIDCClientByID(ctx, clientID)
	if err != nil {
		return err
	}
	if client.secretHash == nil {
		return ErrInvalidSecret
	}
	if !ConstantTimeCompare(hashClientSecret(clientID, secret), client.secretHash) {
		return ErrInvalidSecret
	}
	return nil
}

// ListOIDCClients returns registered relying parties.
func (s *Store) ListOIDCClients(ctx context.Context) ([]*OIDCClient, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c.entity_id, c.client_id, e.name, c.auth_method, c.redirect_uris,
		       c.scopes, c.require_pkce, c.dev_mode
		  FROM oidc_clients c
		  JOIN entities e ON e.id = c.entity_id
		 WHERE e.disabled_at IS NULL
		 ORDER BY e.name`)
	if err != nil {
		return nil, fmt.Errorf("store: listing clients: %w", err)
	}
	defer rows.Close()

	var out []*OIDCClient
	for rows.Next() {
		var (
			c          OIDCClient
			authMethod string
		)
		if err := rows.Scan(&c.EntityID, &c.ClientID, &c.Name, &authMethod,
			&c.RedirectURIs, &c.Scopes, &c.RequirePKCE, &c.DevMode); err != nil {
			return nil, fmt.Errorf("store: scanning client: %w", err)
		}
		c.AuthMethod = AuthMethod(authMethod)
		out = append(out, &c)
	}
	return out, rows.Err()
}

// hashClientSecret binds the hash to its client, so a secret lifted from one
// row cannot be replayed against another.
func hashClientSecret(clientID, secret string) []byte {
	return argon2.IDKey([]byte(secret), []byte("cardinal-client:"+clientID),
		argonTime, argonMemory, argonThreads, argonKeyLen)
}

// newOpaqueID generates an unguessable identifier.
//
// Used for both client_id and client secrets. Opaque rather than readable
// because client_id travels in browser URLs and referrer headers, so a
// meaningful one leaks the shape of internal systems.
func newOpaqueID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: generating identifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// insertEntityTx creates an entity inside an existing transaction.
func insertEntityTx(ctx context.Context, tx pgx.Tx, e *directory.Entity) error {
	err := tx.QueryRow(ctx, `
		INSERT INTO entities (id, type, name, display_name, attrs)
		VALUES ($1, $2, $3, nullif($4, ''), $5)
		RETURNING created_at, updated_at`,
		e.ID, string(e.Type), e.Name, e.DisplayName, e.Attrs,
	).Scan(&e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		if pgErrCode(err) == codeUniqueViolation {
			return fmt.Errorf("%w: a %s named %q already exists",
				directory.ErrAlreadyExists, e.Type, e.Name)
		}
		return fmt.Errorf("store: creating entity: %w", err)
	}
	return nil
}
