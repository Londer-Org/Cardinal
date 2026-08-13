package api

import (
	"context"

	"go.londer.be/cardinal/internal/directory"
)

// Entities, as the API sees them.

// CreateRequest asks for one new entity.
type CreateRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`

	// Owner is the application a group exists for. Only a group has one, and
	// the server refuses it on anything else rather than ignoring it.
	Owner string `json:"owner,omitempty"`
}

// Created is what came back.
type Created struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	ID          string `json:"id"`
	Type        string `json:"type"`
	Owner       string `json:"owner"`
}

// Availability is what disabling or enabling something ended. Both counts are
// zero for an enable, which restores neither.
type Availability struct {
	Name            string `json:"name"`
	SessionsRevoked int64  `json:"sessionsRevoked"`
	TokensRevoked   int    `json:"tokensRevoked"`
}

// Create makes one entity of the given type.
func (c *Client) Create(ctx context.Context, kind directory.Type, req CreateRequest) (Created, error) {
	var out Created
	err := c.post(ctx, "/api/directory/"+kind.Plural(), req, &out)
	return out, err
}

// CreateUser makes a person, optionally with an enrolment link in the same
// request. Users have their own endpoint because no other type can be signed
// into, so no other type has anything to invite.
func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (CreatedUser, error) {
	var out CreatedUser
	err := c.post(ctx, "/api/directory/users", req, &out)
	return out, err
}

// CreateUserRequest asks for one new person.
type CreateUserRequest struct {
	Login       string `json:"login"`
	DisplayName string `json:"displayName,omitempty"`
	Invite      bool   `json:"invite,omitempty"`
}

// CreatedUser is what came back. The invitation is present only if one was
// asked for, and is the only time that URL is ever returned.
type CreatedUser struct {
	Login         string `json:"login"`
	InvitationURL string `json:"invitationUrl"`
	ExpiresAt     string `json:"expiresAt"`
}

// Disable takes an entity out of service, ending its sessions and tokens.
func (c *Client) Disable(ctx context.Context, kind directory.Type, name string) (Availability, error) {
	var out Availability
	err := c.del(ctx, "/api/directory/"+kind.Plural()+"/"+escape(name), &out)
	return out, err
}

// Enable undoes a disable.
func (c *Client) Enable(ctx context.Context, kind directory.Type, name string) (Availability, error) {
	var out Availability
	err := c.post(ctx,
		"/api/directory/"+kind.Plural()+"/"+escape(name)+"/enable", nil, &out)
	return out, err
}
