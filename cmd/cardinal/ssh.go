package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Logging into a machine.
//
// The command the whole host-access design is for, and until now it did not
// exist: the endpoint had been there since Phase 4 and nothing could reach it,
// because issuing a certificate needs a device-bound session and a terminal
// cannot perform a WebAuthn ceremony.
//
// So the ceremony happens where ceremonies happen. This opens a browser, waits
// on a loopback listener for the console to send back a code, exchanges that
// code for a session that inherits the passkey, asks for a certificate, and
// hands the certificate to ssh-agent with the lifetime the certificate itself
// carries. Nothing is written to disk.
//
// Authorization happens here, at issuance, and not at login (ADR 0006). By the
// time `ssh` runs, the decision has been made and recorded, and sshd will do
// nothing but check a signature.

func runSSH(ctx context.Context, args []string) error {
	// `ssh ca ...` is authority administration and predates this command.
	if len(args) > 0 && args[0] == "ca" {
		return runSSHCA(ctx, args[1:])
	}

	fs := flag.NewFlagSet("ssh", flag.ContinueOnError)
	serverFlag := fs.String("server", "", "base URL of the Cardinal server")
	account := fs.String("l", "", "log in as this local account (default: your own login)")
	printOnly := fs.Bool("print", false, "print the certificate and exit, without connecting")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal ssh [user@]<host> [-server <url>]", errUsage)
	}

	host := pos[0]
	localAccount := *account
	// `cardinal ssh deploy@web-01`, which is how people already write it.
	if before, after, ok := strings.Cut(host, "@"); ok {
		localAccount, host = before, after
	}

	base, err := serverURL(*serverFlag)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}

	session, err := signIn(ctx, client, base)
	if err != nil {
		return err
	}

	// A fresh keypair per invocation, held in memory and never written down.
	//
	// Reusing ~/.ssh/id_ed25519 would work and is worse: that key outlives the
	// certificate by years, and the point of a certificate that expires in
	// minutes is that nothing durable is left behind if the machine is lost.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating a key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("encoding the public key: %w", err)
	}

	if localAccount == "" {
		localAccount = session.Login
	}
	if localAccount == "" {
		return errors.New("could not tell which local account to ask for; pass -l")
	}

	cert, err := requestCertificate(ctx, client, base, session.Token, host, localAccount,
		string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPub))))
	if err != nil {
		return err
	}

	parsed, err := parseCertificate(cert.Certificate)
	if err != nil {
		return err
	}
	expires := time.Unix(int64(parsed.ValidBefore), 0) //nolint:gosec // an SSH timestamp, bounded by the CA that signed it

	fmt.Fprintf(os.Stderr, "  certificate for %s as %s, valid until %s\n",
		cert.Host, strings.Join(cert.Principals, ", "), expires.Local().Format(time.Kitchen))

	if *printOnly {
		fmt.Println(cert.Certificate)
		return nil
	}

	if err := addToAgent(ctx, priv, parsed, expires); err != nil {
		return err
	}

	// exec rather than a wrapper. ssh wants a terminal, and anything this
	// process did in between — proxying, reading, buffering — would be a way
	// for it to be wrong about a connection it has no business being inside.
	return runSSHClient(ctx, localAccount, host)
}

// signIn obtains a session by borrowing a ceremony from the browser.
type cliSession struct {
	Token string `json:"token"`
	Login string `json:"-"`
}

func signIn(ctx context.Context, client *http.Client, base string) (*cliSession, error) {
	// The verifier never leaves this process. What travels through the browser
	// is its hash on the way out and a code on the way back, and neither is
	// worth anything without the other.
	verifier, err := randomString()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	verifierHash := base64.RawURLEncoding.EncodeToString(sum[:])

	state, err := randomString()
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
	defer func() { _ = listener.Close() }() //nolint:errcheck // best effort; the server below closes it too

	// The address the kernel actually assigned. Asserted rather than assumed:
	// a listener that is not TCP here would mean the Listen call above changed,
	// and silently formatting a zero port would send the browser somewhere
	// nothing is listening.
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
		"verifier_hash": {verifierHash},
	}.Encode()

	fmt.Fprintf(os.Stderr, "  approve this terminal at:\n\n    %s\n\n", approve)
	openBrowser(approve)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-problems:
		return nil, err
	case <-time.After(2 * time.Minute):
		return nil, errors.New("nobody approved the terminal within two minutes")
	case code := <-codes:
		return exchange(ctx, client, base, code, verifier)
	}
}

func exchange(ctx context.Context, client *http.Client, base, code, verifier string) (*cliSession, error) {
	var out struct {
		Token       string `json:"token"`
		Subject     string `json:"subject"`
		DeviceBound bool   `json:"deviceBound"`
	}
	if err := postJSON(ctx, client, base+"/api/cli/exchange", "",
		map[string]string{"code": code, "verifier": verifier}, &out); err != nil {
		return nil, err
	}
	if !out.DeviceBound {
		// Should be unreachable — the session inherits the console's ceremony —
		// and worth refusing rather than discovering from a denial later, which
		// would read as a policy problem.
		return nil, errors.New("the session issued is not device-bound, so no certificate could be issued with it")
	}

	// The login, for the default local account. Asked separately because the
	// exchange deliberately returns a session and not a profile.
	var me struct {
		Login string `json:"login"`
	}
	if err := getJSON(ctx, client, base+"/api/auth/me", out.Token, &me); err != nil {
		return nil, err
	}
	return &cliSession{Token: out.Token, Login: me.Login}, nil
}

type certificateResponse struct {
	Certificate string   `json:"certificate"`
	Principals  []string `json:"principals"`
	Host        string   `json:"host"`
}

func requestCertificate(
	ctx context.Context, client *http.Client, base, token, host, account, publicKey string,
) (*certificateResponse, error) {
	var out certificateResponse
	err := postJSON(ctx, client, base+"/api/ssh/certificate", token, map[string]string{
		"host":         host,
		"localAccount": account,
		"publicKey":    publicKey,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func parseCertificate(authorized string) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		return nil, fmt.Errorf("reading the certificate Cardinal issued: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("the server returned a public key rather than a certificate")
	}
	return cert, nil
}

const approvedPage = `<!doctype html><meta charset="utf-8">
<title>Terminal approved</title>
<body style="font-family:system-ui;margin:4rem auto;max-width:32rem;line-height:1.5">
<h1 style="font-size:1.25rem">Approved</h1>
<p>You can close this tab and return to your terminal.</p>
</body>`

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating a random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// serverURL resolves where Cardinal is, preferring what was asked for.
func serverURL(flagValue string) (string, error) {
	if flagValue != "" {
		return strings.TrimRight(flagValue, "/"), nil
	}
	if env := os.Getenv("CARDINAL_SERVER"); env != "" {
		return strings.TrimRight(env, "/"), nil
	}
	if cfg, err := loadConfigForCheck(""); err == nil && cfg.Server.PublicURL != "" {
		return strings.TrimRight(cfg.Server.PublicURL, "/"), nil
	}
	return "", errors.New("no server URL: pass -server, set CARDINAL_SERVER, " +
		"or run where a configuration file names one")
}

// openBrowser is best effort, and the URL is printed first for that reason.
//
// A headless machine, an SSH session, a locked-down desktop — all of them are
// ordinary places to run this, and none of them will open anything. Printing
// first means the command works identically when nothing happens.
func openBrowser(target string) {
	var cmd *exec.Cmd
	switch {
	case commandExists("xdg-open"):
		cmd = exec.Command("xdg-open", target) //nolint:gosec,noctx // a URL this process built, and it must outlive the request
	case commandExists("open"):
		cmd = exec.Command("open", target) //nolint:gosec,noctx // as above
	default:
		return
	}
	_ = cmd.Start() //nolint:errcheck // the URL was printed; a browser that will not open is not a failure
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// runSSHClient execs ssh with the certificate already in the agent.
func runSSHClient(ctx context.Context, account, host string) error {
	path, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh is not on PATH: %w", err)
	}
	cmd := exec.CommandContext(ctx, path, account+"@"+host) //nolint:gosec // both come from this process's own arguments
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// jsonError is what Cardinal returns when it refuses.
type jsonError struct {
	Error  string   `json:"error"`
	Policy []string `json:"policy"`
	Reason string   `json:"reason"`
}

func postJSON(ctx context.Context, client *http.Client, endpoint, token string, body, out any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(client, req, out)
}

func getJSON(ctx context.Context, client *http.Client, endpoint, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(client, req, out)
}

func do(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("reaching %s: %w", req.URL.Host, err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing actionable remains once the body is read

	if resp.StatusCode >= 400 {
		var refusal jsonError
		if json.NewDecoder(resp.Body).Decode(&refusal) == nil && refusal.Error != "" {
			// The deciding policy, when there is one. "Why was I denied" is a
			// feature of this system and there is no reason for the command
			// line to be the one place that cannot answer it.
			if len(refusal.Policy) > 0 {
				return fmt.Errorf("%s (policy: %s)", refusal.Error, strings.Join(refusal.Policy, ", "))
			}
			return errors.New(refusal.Error)
		}
		return fmt.Errorf("%s returned %s", req.URL.Path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
