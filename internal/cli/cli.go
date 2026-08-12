// Package cli is the command line, minus the transport.
//
// `cmd/cardinal` dispatches; this decides. The split is not tidiness: the old
// layout mixed flag parsing, database access and printing in every file, so
// adding an output format or an authentication mode touched all of them.
package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.londer.be/cardinal/internal/cli/api"
	"go.londer.be/cardinal/internal/cli/auth"
)

// ErrUsage means the arguments were wrong, and the caller should print usage.
var ErrUsage = errors.New("usage")

// Client returns an API client for a server, signing in if there is no usable
// cached session.
//
// This is where a client command begins, and the reason it is one function: a
// command that decided for itself when to sign in would be a command that could
// forget to, and the failure would be a confusing 401 rather than a browser
// window.
func Client(ctx context.Context, base string) (*api.Client, error) {
	reauth := func(ctx context.Context) (*auth.Session, error) {
		return signIn(ctx, base)
	}

	session, err := auth.Cached(base)
	if err == nil {
		return api.New(base, session, reauth), nil
	}

	session, err = signIn(ctx, base)
	if err != nil {
		return nil, err
	}
	return api.New(base, session, reauth), nil
}

// signIn runs whichever flow can work here, and says which it chose.
//
// Loopback needs a browser that can reach *this machine's* loopback, which is
// not the same as a browser existing: over SSH the approval is redirected to
// the machine the browser runs on, and the terminal waits for something that
// cannot arrive. So the choice is made and announced rather than assumed.
func signIn(ctx context.Context, base string) (*auth.Session, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	if !auth.CanUseLoopback() {
		return nil, errors.New(
			"this terminal cannot complete a browser sign-in: there is no browser " +
				"here, or this is an SSH session and the approval would be sent to " +
				"the machine your browser runs on.\n" +
				"  The flow that works from anywhere is not built yet (ADR 0033); " +
				"until it is, run this where your browser is")
	}

	fmt.Fprintf(os.Stderr, "  signing in to %s\n", base)
	session, err := auth.Loopback(ctx, client, base)
	if err != nil {
		return nil, err
	}
	if err := auth.Remember(base, session); err != nil {
		// Signed in, and the next command will have to do it again. Worth
		// saying and not worth failing for.
		fmt.Fprintf(os.Stderr, "  (could not cache the session: %v)\n", err)
	}
	fmt.Fprintf(os.Stderr, "  signed in as %s\n\n", session.Login)
	return session, nil
}
