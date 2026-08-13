package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// The JSON plumbing, moved here from `cardinal ssh` so there is one copy.
//
// It lives in auth rather than api because the sign-in exchange needs it before
// there is a client to hold a token, and a package that imported api to obtain
// a session that api needs to be constructed would be a cycle.

// Refused is a refusal the server explained.
type Refused struct {
	Status int
	Reason string

	// Policy names the deciding rule when there is one. "Why was I denied" is a
	// feature of this system and there is no reason for the command line to be
	// the one place that cannot answer it.
	Policy []string
}

func (r *Refused) Error() string {
	if len(r.Policy) > 0 {
		return fmt.Sprintf("%s (policy: %s)", r.Reason, strings.Join(r.Policy, ", "))
	}
	return r.Reason
}

// Unauthorized reports a session the server no longer accepts, which is the one
// refusal a caller can do something about without a person: sign in again.
func (r *Refused) Unauthorized() bool { return r.Status == http.StatusUnauthorized }

type jsonError struct {
	Error  string   `json:"error"`
	Policy []string `json:"policy"`
}

// PostJSON sends a body and decodes the reply.
func PostJSON(ctx context.Context, c *http.Client, endpoint, token string, body, out any) error {
	return SendJSON(ctx, c, http.MethodPost, endpoint, token, body, out)
}

// SendJSON writes with a method of the caller's choosing. PUT replaces a whole
// setting where POST adds to a collection, and an API that means the difference
// needs a client that can say it.
func SendJSON(ctx context.Context, c *http.Client, method, endpoint, token string, body, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return Do(c, req, token, out)
}

// GetJSON reads.
func GetJSON(ctx context.Context, c *http.Client, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	return Do(c, req, token, out)
}

// Do sends a prepared request, attaches the credential, and turns a refusal
// into an error carrying what the server said.
func Do(c *http.Client, req *http.Request, token string, out any) error {
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// The URL is one this process built from the configured server plus a fixed
	// path, never from a value a server returned, so there is no redirect or
	// user-supplied host for the taint analysis to be right about.
	resp, err := c.Do(req) //nolint:gosec // G704: the endpoint comes from configuration, not from a response
	if err != nil {
		return fmt.Errorf("reaching %s: %w", req.URL.Host, err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode >= 400 {
		refusal := &Refused{Status: resp.StatusCode}
		var body jsonError
		if json.NewDecoder(resp.Body).Decode(&body) == nil && body.Error != "" {
			refusal.Reason = body.Error
			refusal.Policy = body.Policy
			return refusal
		}
		refusal.Reason = fmt.Sprintf("%s returned %s", req.URL.Path, resp.Status)
		return refusal
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("reading the reply from %s: %w", req.URL.Path, err)
	}
	return nil
}
