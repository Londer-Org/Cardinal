package api

import (
	"context"
	"net/url"
	"time"

	"go.londer.be/cardinal/internal/directory"
)

// The directory as a table of entities.

// Entity is one row of it.
type Entity struct {
	Type        string     `json:"type"`
	Name        string     `json:"name"`
	ID          string     `json:"id"`
	DisplayName string     `json:"displayName"`
	CreatedAt   time.Time  `json:"createdAt"`
	DisabledAt  *time.Time `json:"disabledAt"`
}

// Active reports whether it is in service. Nil rather than a zero time, so
// "disabled at the zero instant" cannot be mistaken for it.
func (e Entity) Active() bool { return e.DisabledAt == nil }

// Membership is one group an entity belongs to, and how it got there.
type Membership struct {
	Group  string `json:"group"`
	Direct bool   `json:"direct"`
	Depth  int    `json:"depth"`
}

// EntityDetail is one entity and what it belongs to.
type EntityDetail struct {
	Entity

	Memberships []Membership `json:"memberships"`
}

// Entities lists what is in the directory. An empty kind means every type;
// all includes the ones taken out of service.
func (c *Client) Entities(ctx context.Context, kind directory.Type, all bool) ([]Entity, error) {
	query := url.Values{}
	if kind != "" {
		query.Set("type", string(kind))
	}
	if all {
		query.Set("all", "true")
	}

	path := "/api/directory/entities"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}

	var out struct {
		Entities []Entity `json:"entities"`
	}
	err := c.get(ctx, path, &out)
	return out.Entities, err
}

// Entity describes one, with its memberships resolved through nested groups.
func (c *Client) Entity(ctx context.Context, kind directory.Type, name string) (EntityDetail, error) {
	var out EntityDetail
	err := c.get(ctx,
		"/api/directory/entities/"+escape(string(kind))+"/"+escape(name), &out)
	return out, err
}
