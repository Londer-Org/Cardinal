package api

import (
	"context"
)

// Applications, as the API sees them.

// Application is one entry in the listing: an entity of type application,
// which may or may not also be an OIDC relying party.
type Application struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Disabled    bool   `json:"disabled"`

	// Hostnames it answers to through forwardAuth. Empty is not an error and
	// not unusual: an application reached only over OIDC has none.
	Hostnames []string `json:"hostnames"`

	// OIDC is null when the application speaks no OpenID Connect. "Public
	// client" and "no client" are different facts, and a flattened zero value
	// in this position would assert the first.
	OIDC *OIDCClient `json:"oidc"`
}

// OIDCClient is the relying-party half of an application.
type OIDCClient struct {
	ClientID     string   `json:"clientId"`
	Name         string   `json:"name"`
	AuthMethod   string   `json:"authMethod"`
	Public       bool     `json:"public"`
	RedirectURIs []string `json:"redirectUris"`
	Scopes       []string `json:"scopes"`

	RequirePKCE    bool `json:"requirePkce"`
	RequireConsent bool `json:"requireConsent"`
	DevMode        bool `json:"devMode"`

	AccessTokenLifetime string `json:"accessTokenLifetime"`
}

// RegisterRequest asks for a new application. No redirect URIs means no OpenID
// Connect, which is a whole legitimate category rather than an incomplete
// request: an application behind the proxy has nothing to redirect to.
type RegisterRequest struct {
	Name         string   `json:"name"`
	DisplayName  string   `json:"displayName,omitempty"`
	RedirectURIs []string `json:"redirectUris,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`

	Confidential   bool `json:"confidential,omitempty"`
	RequireConsent bool `json:"requireConsent,omitempty"`
	DevMode        bool `json:"devMode,omitempty"`
}

// Registered is what came back. Secret appears exactly once, here, and is
// never recoverable — only its hash is stored.
type Registered struct {
	Name     string `json:"name"`
	ClientID string `json:"clientId"`
	Secret   string `json:"secret"`
}

// Applications lists every application, relying party or not.
func (c *Client) Applications(ctx context.Context) ([]Application, error) {
	var out []Application
	err := c.get(ctx, "/api/applications", &out)
	return out, err
}

// Register creates an application.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (Registered, error) {
	var out Registered
	err := c.post(ctx, "/api/applications", req, &out)
	return out, err
}

// HostnameAdded reports what registering an address achieved. InAnyGroup is
// false when the application is in no group, which means the shipped policy set
// admits nobody to it — findable, and refused to everybody.
type HostnameAdded struct {
	Application string `json:"application"`
	Hostname    string `json:"hostname"`
	InAnyGroup  bool   `json:"inAnyGroup"`
}

// AddHostname makes an application answer for an address behind the proxy.
func (c *Client) AddHostname(ctx context.Context, app, hostname string) (HostnameAdded, error) {
	var out HostnameAdded
	err := c.post(ctx, "/api/applications/"+escape(app)+"/hostnames",
		map[string]string{"hostname": hostname}, &out)
	return out, err
}

// RemoveHostname stops it answering for one.
func (c *Client) RemoveHostname(ctx context.Context, app, hostname string) error {
	return c.del(ctx, "/api/applications/"+escape(app)+"/hostnames/"+escape(hostname), nil)
}

// Projection is which groups an application is told about.
type Projection struct {
	Mode   string            `json:"mode"`
	Groups []ProjectionGroup `json:"groups"`

	// TotalGroups is what makes `all` legible: "told about every group" is a
	// setting, and "told about 14 groups, 12 of which it does not own" is an
	// argument.
	TotalGroups int `json:"totalGroups"`
}

// ProjectionGroup is one group in that answer. Owned separates a group that
// belongs to the application from one it was granted sight of.
type ProjectionGroup struct {
	Name  string `json:"name"`
	Owned bool   `json:"owned"`
}

// Projection reports which groups an application is told about.
func (c *Client) Projection(ctx context.Context, app string) (Projection, error) {
	var out Projection
	err := c.get(ctx, "/api/applications/"+escape(app)+"/projection", &out)
	return out, err
}

// SetProjectionMode changes which groups it is told about.
func (c *Client) SetProjectionMode(ctx context.Context, app, mode string) error {
	return c.put(ctx, "/api/applications/"+escape(app)+"/projection",
		map[string]string{"mode": mode}, nil)
}

// GrantSight lets an application see a group it does not own.
func (c *Client) GrantSight(ctx context.Context, app, group string) error {
	return c.post(ctx,
		"/api/applications/"+escape(app)+"/projection/groups/"+escape(group), nil, nil)
}

// RevokeSight takes that away.
func (c *Client) RevokeSight(ctx context.Context, app, group string) error {
	return c.del(ctx, "/api/applications/"+escape(app)+"/projection/groups/"+escape(group), nil)
}
