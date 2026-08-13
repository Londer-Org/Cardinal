package api

import (
	"context"
	"net/url"
	"time"
)

// Membership, as the API sees it.

// Grant is one membership, whether or not it is still in force.
type Grant struct {
	Group  string     `json:"group"`
	Member string     `json:"member"`
	From   time.Time  `json:"from"`
	Until  *time.Time `json:"until"`
	Reason string     `json:"reason"`

	// GrantedBy is who made it. Empty on the history endpoint, which reports
	// periods rather than actors.
	GrantedBy string `json:"grantedBy"`

	// Current is set by the history endpoint, which returns grants that have
	// ended alongside the one that has not.
	Current bool `json:"current"`
}

type groupResponse struct {
	Name        string  `json:"name"`
	DisplayName string  `json:"displayName"`
	System      bool    `json:"system"`
	Owner       string  `json:"owner"`
	At          string  `json:"at"`
	Members     []Grant `json:"members"`
}

type userResponse struct {
	Login       string  `json:"login"`
	DisplayName string  `json:"displayName"`
	Memberships []Grant `json:"memberships"`
}

// Members lists who is in a group, at an instant when one is given.
func (c *Client) Members(ctx context.Context, group string, at time.Time) ([]Grant, error) {
	var out groupResponse
	if err := c.get(ctx, "/api/directory/groups/"+escape(group)+atQuery(at), &out); err != nil {
		return nil, err
	}
	return out.Members, nil
}

// Memberships lists the groups somebody is directly in.
func (c *Client) Memberships(ctx context.Context, login string, at time.Time) ([]Grant, error) {
	var out userResponse
	if err := c.get(ctx, "/api/directory/users/"+escape(login)+atQuery(at), &out); err != nil {
		return nil, err
	}
	return out.Memberships, nil
}

// History is every grant ever made of one membership.
type History struct {
	Group    string  `json:"group"`
	Member   string  `json:"member"`
	At       string  `json:"at"`
	MemberAt *bool   `json:"memberAt"`
	Grants   []Grant `json:"grants"`
}

// GrantHistory returns them, and answers for an instant when one is given.
func (c *Client) GrantHistory(ctx context.Context, group, member string, at time.Time) (*History, error) {
	var out History
	path := "/api/directory/groups/" + escape(group) + "/members/" + escape(member) + "/history"
	if err := c.get(ctx, path+atQuery(at), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// atQuery renders the instant, or nothing for now.
func atQuery(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return "?" + url.Values{"at": {at.UTC().Format(time.RFC3339)}}.Encode()
}

// GrantRequest is a membership being made.
//
// Until is a pointer because absent and "no end" are the same thing to the
// server, and a zero timestamp is not: sending one would ask for a grant that
// expired in the year zero.
type GrantRequest struct {
	Member string     `json:"member"`
	Until  *time.Time `json:"until,omitempty"`
	Reason string     `json:"reason,omitempty"`
}

// Grant adds somebody to a group.
func (c *Client) Grant(ctx context.Context, group string, req GrantRequest) error {
	return c.post(ctx, "/api/directory/groups/"+escape(group)+"/members", req, nil)
}

// Revoke ends a membership, keeping its history. The zero time means now.
func (c *Client) Revoke(ctx context.Context, group, member string, at time.Time) error {
	return c.del(ctx, "/api/directory/groups/"+escape(group)+"/members/"+escape(member)+atQuery(at), nil)
}
