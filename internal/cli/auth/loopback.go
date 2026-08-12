package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"
)

// Signing in by having the console redirect to this machine.
//
// What this needs is not a browser — it is a browser that can reach *this
// machine's* loopback. Those are different conditions, and the second is false
// in the ordinary case of administering a server over SSH: the approval is
// redirected to 127.0.0.1 on whatever machine the browser is running on, which
// is not this one, and the terminal waits for something that will never arrive.
//
// So this flow is chosen rather than assumed, and the caller says which one it
// picked. The device-code flow (ADR 0033) is the one for everywhere else.

// approvalWindow is how long the terminal waits for somebody to approve it.
const approvalWindow = 2 * time.Minute

// Loopback runs the browser-redirect sign-in and returns the session.
func Loopback(ctx context.Context, c *http.Client, base string) (*Session, error) {
	verifier, err := RandomString()
	if err != nil {
		return nil, err
	}
	state, err := RandomString()
	if err != nil {
		return nil, err
	}

	// Port zero: the operating system picks one that is free. A fixed port is a
	// race with anything else already listening, and on a shared machine it is
	// a race somebody else can win on purpose.
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("opening a loopback listener: %w", err)
	}
	defer func() { _ = listener.Close() }() //nolint:errcheck // the server below closes it too

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("loopback listener is %T, not TCP", listener.Addr())
	}
	callback := fmt.Sprintf("http://127.0.0.1:%d/callback", addr.Port)

	codes := make(chan string, 1)
	problems := make(chan error, 1)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			problems <- errors.New("the browser came back with the wrong state, so the response was discarded")
			return
		}
		code := q.Get("code")
		if code == "" {
			http.Error(w, "no code", http.StatusBadRequest)
			problems <- errors.New("the browser came back without a code")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, approvedPage) //nolint:errcheck // the header is already written, so the status cannot be changed
		codes <- code
	})
	srv.Handler = mux
	go func() { _ = srv.Serve(listener) }() //nolint:errcheck // Serve always returns non-nil on close
	defer func() { _ = srv.Close() }()      //nolint:errcheck // best effort on a listener already being torn down

	approve := base + "/cli-login?" + url.Values{
		"callback":      {callback},
		"state":         {state},
		"verifier_hash": {VerifierHash(verifier)},
	}.Encode()

	fmt.Fprintf(os.Stderr, "  approve this terminal at:\n\n    %s\n\n", approve)
	openBrowser(approve)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-problems:
		return nil, err
	case <-time.After(approvalWindow):
		return nil, errors.New(
			"nobody approved the terminal within two minutes — if you opened that " +
				"link on another machine, the approval was sent to its loopback " +
				"rather than this one and could not arrive")
	case code := <-codes:
		return Exchange(ctx, c, base, code, verifier)
	}
}

// CanUseLoopback reports whether the browser is likely to be able to reach this
// machine.
//
// A heuristic, and allowed to be one: both flows end in the same session, so
// getting this wrong costs a fallback rather than a credential. SSH_CONNECTION
// is the signal that matters — a browser opened from that session runs on the
// other end of it.
func CanUseLoopback() bool {
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return false
	}
	return browserCommand() != ""
}

func browserCommand() string {
	for _, name := range []string{"xdg-open", "open"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	return ""
}

func openBrowser(target string) {
	name := browserCommand()
	if name == "" {
		return
	}
	//nolint:gosec,noctx // a URL this process built, and it must outlive the request
	_ = exec.Command(name, target).Start() //nolint:errcheck // the URL was printed; a browser that will not open is not a failure
}

const approvedPage = `<!doctype html><meta charset="utf-8">
<title>Terminal approved</title>
<body style="font-family:system-ui;margin:4rem auto;max-width:32rem;line-height:1.5">
<h1 style="font-size:1.25rem">Approved</h1>
<p>You can close this tab and return to your terminal.</p>
</body>`
