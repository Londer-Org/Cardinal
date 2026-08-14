package api

import (
	"context"
	"time"

	"go.londer.be/cardinal/internal/directory"
)

// Access tokens, as the API sees them.

// Token is one entry in a listing. The value itself is never in one — only its
// prefix, which identifies a token without being able to authenticate as it.
type Token struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Prefix string `json:"prefix"`

	CreatedAt  time.Time  `json:"createdAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	Expired    bool       `json:"expired"`
	Scopes     []string   `json:"scopes"`
}

// IssueTokenRequest asks for a token on a service account's behalf.
//
// Days rather than a duration, matching the field the console fills from a
// select: a free-text duration is a way to typo "90d" into "90m".
type IssueTokenRequest struct {
	Name   string   `json:"name"`
	Days   int      `json:"days,omitempty"`
	Scopes []string `json:"scopes"`
}

// IssuedToken is what came back. Token is the only time the value is ever
// returned — everything after stores and compares a hash.
type IssuedToken struct {
	Subject   string    `json:"subject"`
	Token     string    `json:"token"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// IssueToken creates a token for a service account. The server refuses one for
// a person, who issues their own.
func (c *Client) IssueToken(ctx context.Context, kind directory.Type, name string, req IssueTokenRequest) (IssuedToken, error) {
	var out IssuedToken
	err := c.post(ctx, "/api/directory/"+kind.Plural()+"/"+escape(name)+"/tokens", req, &out)
	return out, err
}

// Tokens lists a subject's tokens, disclosing no value.
func (c *Client) Tokens(ctx context.Context, kind directory.Type, name string) ([]Token, error) {
	var out struct {
		Tokens []Token `json:"tokens"`
	}
	err := c.get(ctx, "/api/directory/"+kind.Plural()+"/"+escape(name)+"/tokens", &out)
	return out.Tokens, err
}

// RevokeToken ends one of a subject's tokens.
func (c *Client) RevokeToken(ctx context.Context, kind directory.Type, name, id string) error {
	return c.del(ctx,
		"/api/directory/"+kind.Plural()+"/"+escape(name)+"/tokens/"+escape(id), nil)
}
