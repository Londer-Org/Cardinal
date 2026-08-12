package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/auth"
	"go.londer.be/cardinal/internal/cli/direct"
	"golang.org/x/crypto/ssh"
)

// Logging into a machine — `cardinal ssh web-01`.
//
// One of three ssh files here, and the one a person uses. The authority is
// administered in sshauthority.go; sshagent.go hands the certificate to
// ssh-agent.
//
// The command the whole host-access design is for, and the last piece written:
// the issuing endpoint existed long before anything could reach it, because a
// certificate needs a device-bound session and a terminal cannot perform a
// WebAuthn ceremony.
//
// So the ceremony happens where ceremonies happen, through the shared sign-in
// in internal/cli: a loopback handoff when the browser can reach this machine,
// and a printed code when it cannot. The session inherits the passkey either
// way; this asks for a certificate with it and hands the certificate to
// ssh-agent with the lifetime the certificate itself carries. Nothing is
// written to disk.
//
// It had its own copy of that flow until recently, which meant the command most
// often run on a machine somebody is SSH'd into was the one that could not be
// signed in from anywhere else.
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
	pos, err := cli.Parse(fs, args)
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

	// The shared flow, which chooses between the loopback handoff and the
	// device code. `cardinal ssh` is the command most often run on a machine
	// somebody is SSH'd into, so it is the one that most needed the second.
	session, err := cli.SignIn(ctx, base)
	if err != nil {
		return err
	}
	if !session.DeviceBound {
		// Refused here rather than discovered from the policy denial the
		// certificate request would produce, which reads as a policy problem.
		return errors.New(
			"the session is not device-bound, so no certificate could be issued with it")
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

type certificateResponse struct {
	Certificate string   `json:"certificate"`
	Principals  []string `json:"principals"`
	Host        string   `json:"host"`
}

func requestCertificate(
	ctx context.Context, client *http.Client, base, token, host, account, publicKey string,
) (*certificateResponse, error) {
	var out certificateResponse
	err := auth.PostJSON(ctx, client, base+"/api/ssh/certificate", token, map[string]string{
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

// serverURL resolves where Cardinal is, preferring what was asked for.
func serverURL(flagValue string) (string, error) {
	if flagValue != "" {
		return strings.TrimRight(flagValue, "/"), nil
	}
	if env := os.Getenv("CARDINAL_SERVER"); env != "" {
		return strings.TrimRight(env, "/"), nil
	}
	if cfg, err := direct.LoadConfig(""); err == nil && cfg.Server.PublicURL != "" {
		return strings.TrimRight(cfg.Server.PublicURL, "/"), nil
	}
	return "", errors.New("no server URL: pass -server, set CARDINAL_SERVER, " +
		"or run where a configuration file names one")
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
