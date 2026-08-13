// Package api is the typed client for Cardinal's admin API.
//
// It exists so that a command says what it wants rather than how to ask: a
// command that builds URLs and decodes JSON is a command that has to be read
// carefully to find out which endpoint it touches, and there are forty of them.
//
// Nothing here reaches PostgreSQL, and an import test enforces that. One
// `store.Open` in a command is all it takes to restore the situation ADR 0033
// exists to remove, and it would look like an ordinary import.
package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"go.londer.be/cardinal/internal/cli/auth"
)

// Client talks to one Cardinal, as one person.
type Client struct {
	base    string
	session *auth.Session
	http    *http.Client

	// reauth obtains a fresh session when the server stops accepting the one
	// held. Injected rather than called directly so a test can drive the client
	// without a browser.
	reauth func(ctx context.Context) (*auth.Session, error)
}

// New builds a client for a server, using a session already obtained.
func New(base string, session *auth.Session, reauth func(context.Context) (*auth.Session, error)) *Client {
	return &Client{
		base:    base,
		session: session,
		http:    &http.Client{Timeout: 30 * time.Second},
		reauth:  reauth,
	}
}

// Login is who the client is acting as.
func (c *Client) Login() string { return c.session.Login }

// get, post, put and del are the whole surface.
//
// Each retries once after signing in again, and only for a 401: a session that
// expired between two commands is ordinary, and making somebody re-run the
// command to find that out would be a worse interface than the database one
// this replaces.
func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.retrying(ctx, func(token string) error {
		return auth.GetJSON(ctx, c.http, c.base+path, token, out)
	})
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.retrying(ctx, func(token string) error {
		return auth.PostJSON(ctx, c.http, c.base+path, token, body, out)
	})
}

func (c *Client) put(ctx context.Context, path string, body, out any) error {
	return c.retrying(ctx, func(token string) error {
		return auth.SendJSON(ctx, c.http, http.MethodPut, c.base+path, token, body, out)
	})
}

// del has no body, which is what makes it a separate helper rather than send
// with a method argument: every verb that carries one goes through post or put.
func (c *Client) del(ctx context.Context, path string, out any) error {
	return c.retrying(ctx, func(token string) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.base+path, nil)
		if err != nil {
			return err
		}
		return auth.Do(c.http, req, token, out)
	})
}

func (c *Client) retrying(ctx context.Context, call func(token string) error) error {
	err := call(c.session.Token)

	var refused *auth.Refused
	if !errors.As(err, &refused) || !refused.Unauthorized() || c.reauth == nil {
		return err
	}

	session, reauthErr := c.reauth(ctx)
	if reauthErr != nil {
		// The original refusal is what the caller needs to see. Failing to sign
		// in again is a consequence of it, and reporting the consequence would
		// bury the cause.
		return err
	}
	c.session = session
	return call(session.Token)
}

// escape makes a name safe to put in a path.
//
// Group and login names are chosen by people and reach sudoers, SSH principals
// and Cedar identifiers, so they are not assumed to be free of a slash.
func escape(name string) string { return url.PathEscape(name) }
