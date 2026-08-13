package api

import (
	"context"
	"time"
)

// POSIX identity, as the API sees it.

// POSIXIdentity is one number and what comes with it. Number is a uid for a
// user and a gid for a group: one allocator serves both, so the two can never
// collide.
type POSIXIdentity struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Number int    `json:"number"`

	HomeDirectory string `json:"homeDirectory"`
	LoginShell    string `json:"loginShell"`

	// FirstServedAt is when a host was first told this number. Null means it
	// can still be adopted; set means it is on a filesystem somewhere and
	// changing it moves files rather than editing a row.
	FirstServedAt *time.Time `json:"firstServedAt"`
	Adoptable     bool       `json:"adoptable"`
}

// POSIXRequest edits what comes with a number. A nil field is unchanged; the
// number itself is never in a request, because it is permanent once a host has
// been told and there would be no undoing a typo.
type POSIXRequest struct {
	HomeDirectory *string `json:"homeDirectory,omitempty"`
	LoginShell    *string `json:"loginShell,omitempty"`
}

// userPOSIX is the shape the user endpoints answer with, which names the
// number `uid` because in a user's context that is what it is.
type userPOSIX struct {
	UID           int        `json:"uid"`
	HomeDirectory string     `json:"homeDirectory"`
	LoginShell    string     `json:"loginShell"`
	FirstServedAt *time.Time `json:"firstServedAt"`
	Adoptable     bool       `json:"adoptable"`
}

func (u userPOSIX) identity(name string) POSIXIdentity {
	return POSIXIdentity{
		Name:          name,
		Type:          "user",
		Number:        u.UID,
		HomeDirectory: u.HomeDirectory,
		LoginShell:    u.LoginShell,
		FirstServedAt: u.FirstServedAt,
		Adoptable:     u.Adoptable,
	}
}

// AssignPOSIX gives a user a uid, or edits what comes with the one they have.
func (c *Client) AssignPOSIX(ctx context.Context, login string, req POSIXRequest) (POSIXIdentity, error) {
	var out userPOSIX
	err := c.put(ctx, "/api/directory/users/"+escape(login)+"/posix", req, &out)
	return out.identity(login), err
}

// AssignGroupPOSIX gives a group a gid. It carries no home directory and no
// login shell, which is why it is not the same call as a user's.
func (c *Client) AssignGroupPOSIX(ctx context.Context, group string) (POSIXIdentity, error) {
	var out POSIXIdentity
	err := c.put(ctx, "/api/directory/groups/"+escape(group)+"/posix", struct{}{}, &out)
	return out, err
}

// AdoptPOSIX takes a number the fleet already uses, for an account whose files
// exist on disks that recorded the other one.
func (c *Client) AdoptPOSIX(ctx context.Context, login string, number int) (POSIXIdentity, error) {
	var out POSIXIdentity
	err := c.post(ctx, "/api/directory/users/"+escape(login)+"/posix/adopt",
		map[string]int{"number": number}, &out)
	return out, err
}

// POSIXIdentities lists every number handed out, which is what an operator
// needs before adopting anything: the question is "what is already taken".
func (c *Client) POSIXIdentities(ctx context.Context) ([]POSIXIdentity, error) {
	var out struct {
		Identities []POSIXIdentity `json:"identities"`
	}
	err := c.get(ctx, "/api/posix", &out)
	return out.Identities, err
}

// UserPOSIX reads one person's, distinguishing a user who does not exist from
// one who has no number: they need different things done about them.
func (c *Client) UserPOSIX(ctx context.Context, login string) (POSIXIdentity, bool, error) {
	var out struct {
		POSIX *userPOSIX `json:"posix"`
	}
	if err := c.get(ctx, "/api/directory/users/"+escape(login), &out); err != nil {
		return POSIXIdentity{}, false, err
	}
	if out.POSIX == nil {
		return POSIXIdentity{}, false, nil
	}
	return out.POSIX.identity(login), true, nil
}

// GroupPOSIX reads one group's.
func (c *Client) GroupPOSIX(ctx context.Context, name string) (POSIXIdentity, bool, error) {
	var out struct {
		POSIX *struct {
			GID           int        `json:"gid"`
			FirstServedAt *time.Time `json:"firstServedAt"`
			Adoptable     bool       `json:"adoptable"`
		} `json:"posix"`
	}
	if err := c.get(ctx, "/api/directory/groups/"+escape(name), &out); err != nil {
		return POSIXIdentity{}, false, err
	}
	if out.POSIX == nil {
		return POSIXIdentity{}, false, nil
	}
	return POSIXIdentity{
		Name:          name,
		Type:          "group",
		Number:        out.POSIX.GID,
		FirstServedAt: out.POSIX.FirstServedAt,
		Adoptable:     out.POSIX.Adoptable,
	}, true, nil
}
