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

// AuthFlow is which sign-in handoff to use.
//
// The default works it out, and is right often enough that most people will
// never set this. It exists for the cases a heuristic cannot see: a terminal
// multiplexer that outlives the SSH session it was started from, a remote
// desktop where the browser really is here, a machine where opening one would
// be unwelcome.
type AuthFlow string

const (
	// AuthAuto prefers loopback where a browser can reach this machine.
	AuthAuto AuthFlow = ""

	// AuthLoopback delivers approval to this machine, so nobody can be talked
	// into approving somebody else's terminal.
	AuthLoopback AuthFlow = "loopback"

	// AuthDevice prints a code to approve from anywhere, and is phishable in
	// exchange for working when the browser is elsewhere.
	AuthDevice AuthFlow = "device"
)

// ParseAuthFlow reads what somebody asked for.
func ParseAuthFlow(raw string) (AuthFlow, error) {
	switch AuthFlow(raw) {
	case AuthAuto, AuthLoopback, AuthDevice:
		return AuthFlow(raw), nil
	default:
		return AuthAuto, fmt.Errorf(
			"%w: -auth is `loopback` or `device`, and omitting it works it out",
			ErrUsage)
	}
}

// Client returns an API client for a server, signing in if there is no usable
// cached session.
//
// This is where a client command begins, and the reason it is one function: a
// command that decided for itself when to sign in would be a command that could
// forget to, and the failure would be a confusing 401 rather than a browser
// window.
func Client(ctx context.Context, base string, flow AuthFlow) (*api.Client, error) {
	reauth := func(ctx context.Context) (*auth.Session, error) {
		return SignIn(ctx, base, flow)
	}

	session, err := auth.Cached(base)
	if err == nil {
		return api.New(base, session, reauth), nil
	}

	session, err = SignIn(ctx, base, flow)
	if err != nil {
		return nil, err
	}
	return api.New(base, session, reauth), nil
}

// SignIn obtains a session, from the cache when there is a usable one.
//
// Exported because `cardinal ssh` needs it without needing an API client: it
// asks for a certificate and then hands it to ssh-agent, which no typed client
// method describes. Before this it had its own copy of the whole flow, so it
// never gained the device code — and the command most often run on a machine
// somebody is SSH'd into was the one that needed it most.
//
// Runs whichever flow can work here, and says which it chose.
//
// Loopback needs a browser that can reach *this machine's* loopback, which is
// not the same as a browser existing: over SSH the approval is redirected to
// the machine the browser runs on, and the terminal waits for something that
// cannot arrive. So the choice is made and announced rather than assumed.
func SignIn(ctx context.Context, base string, flow AuthFlow) (*auth.Session, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	// Which flow runs is chosen and said out loud. Both end in the same
	// session, so getting it wrong costs a fallback rather than a credential —
	// which is why a heuristic is allowed here at all.
	var (
		session *auth.Session
		err     error
	)
	useLoopback := flow == AuthLoopback || (flow == AuthAuto && auth.CanUseLoopback())
	if useLoopback {
		fmt.Fprintf(os.Stderr, "  signing in to %s\n", base)
		session, err = auth.Loopback(ctx, client, base)
	} else {
		// No browser here, or an SSH session — where a loopback approval would
		// be delivered to the machine the browser runs on and never arrive.
		session, err = auth.Device(ctx, client, base)
	}
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
