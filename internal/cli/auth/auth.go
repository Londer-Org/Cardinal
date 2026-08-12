// Package auth signs a terminal in.
//
// A terminal cannot perform a WebAuthn ceremony: there is no browser in it and
// no way to reach a platform authenticator. So it borrows one. The person
// completes the ceremony where ceremonies happen — in the console — and what
// comes back is a session that *inherits* what that ceremony proved.
//
// Inherits, rather than being granted something weaker, is the whole point. An
// access token would have been far less work and is exactly wrong: it is not
// device-bound, so policy refuses it an SSH certificate (ADR 0018), and making
// it device-bound would put a credential that can reach every machine in the
// fleet into a file on disk with a ninety-day life.
//
// Extracted from `cardinal ssh`, which was the only caller and is now one of
// several. The verifier still never leaves this process: what travels through
// the browser is its hash on the way out and a single-use code on the way back,
// and neither is worth anything without the other.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Session is what a signed-in terminal holds.
type Session struct {
	Token string `json:"token"`

	// Login is the person the session belongs to, asked for separately because
	// the exchange deliberately returns a session and not a profile.
	Login string `json:"login"`

	// DeviceBound is what the ceremony proved. Recorded rather than assumed:
	// a session that is not device-bound cannot obtain an SSH certificate, and
	// finding that out from a refusal later reads as a policy problem.
	DeviceBound bool `json:"deviceBound"`

	// ExpiresAt is when this stops being worth trying. Advisory: the server
	// decides, and a cache that believes its own copy would keep presenting a
	// revoked session.
	ExpiresAt time.Time `json:"expiresAt"`
}

// Exchange turns an approved code into a session.
//
// Two steps because the first ends in a redirect, and a URL is the worst place
// to put a credential — it lands in shell history, in proxy logs, and in the
// browser's address bar. The code is single-use, short-lived, and worthless
// without the verifier the terminal never sent anywhere.
func Exchange(ctx context.Context, c *http.Client, base, code, verifier string) (*Session, error) {
	var out struct {
		Token       string `json:"token"`
		Subject     string `json:"subject"`
		DeviceBound bool   `json:"deviceBound"`
	}
	if err := PostJSON(ctx, c, base+"/api/cli/exchange", "",
		map[string]string{"code": code, "verifier": verifier}, &out); err != nil {
		return nil, err
	}

	var me struct {
		Login string `json:"login"`
	}
	if err := GetJSON(ctx, c, base+"/api/auth/me", out.Token, &me); err != nil {
		return nil, err
	}

	return &Session{
		Token:       out.Token,
		Login:       me.Login,
		DeviceBound: out.DeviceBound,
		// The server's own lifetime is not returned, so this is a floor rather
		// than a promise: the cache stops offering the session at this point,
		// and the server may have ended it sooner.
		ExpiresAt: time.Now().Add(sessionFloor),
	}, nil
}

// sessionFloor is how long a cached session is offered before the flow runs
// again without being asked.
//
// Shorter than any session the server issues, on purpose. Being wrong in this
// direction costs one browser approval; being wrong in the other means
// presenting a credential the server has already forgotten and reporting the
// refusal as though the command failed.
const sessionFloor = 5 * time.Minute

// RandomString is a verifier or a state value.
func RandomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating a random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// VerifierHash is what travels through the browser.
func VerifierHash(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ErrNotSignedIn means there is no usable cached session.
var ErrNotSignedIn = errors.New("not signed in")
