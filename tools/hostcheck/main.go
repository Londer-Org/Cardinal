// Command hostcheck stands in for a real agent so the host-side integration can
// be checked against the real system tools.
//
// The Go tests prove only that each package agrees with a client written from
// the same reading of the specification. That is the trap this project has
// walked into before — a certificate that verifies against itself — so the
// provider is checked with `getent` and the sudoers file with `sudo`, which are
// the only clients whose opinions matter.
//
// Run inside a container by `make verify-host`. Not shipped.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/agent"
	"github.com/arthur-lonfils/cardinal/internal/sshca"
	"github.com/arthur-lonfils/cardinal/internal/sudoers"
	"github.com/arthur-lonfils/cardinal/internal/userdb"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func main() { os.Exit(main1()) }

func main1() int {
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The same path a real assignment takes: server JSON → Assignment →
	// Snapshot → provider. Verifying a hand-built fixture instead would skip
	// the indexing, which is where the user-private group is synthesised.
	assignment := &agent.Assignment{
		Host: "verify",
		Users: []agent.AssignedUser{
			{
				Name: "cardinaltest", UID: 100000, GID: 100000,
				Home: "/home/cardinaltest", Shell: "/bin/bash",
				Groups: []int{100001}, Sudo: true,
			},
			{
				// Resolvable and deliberately not a sudoer, so "sudo grants
				// everybody" and "sudo grants the right people" are
				// distinguishable outcomes.
				Name: "cardinalplain", UID: 100002, GID: 100002,
				Home: "/home/cardinalplain", Shell: "/bin/bash",
			},
		},
		Groups: []agent.AssignedGroup{{
			Name: "cardinalsre", GID: 100001, Members: []string{"cardinaltest"},
		}},
	}
	snapshot := agent.NewSnapshot(assignment)

	// The same render the agent performs, installed the same way — so what sudo
	// is asked about is the real output and not a fixture written to please it.
	content, err := sudoers.Render(assignment.Sudoers(), assignment.Host, time.Time{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := sudoers.Install(ctx, sudoers.DefaultPath, content); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if err := writeHostCertificate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if err := os.MkdirAll(userdb.DefaultRunDir, 0o755); err != nil { //nolint:gosec // matches systemd's own mode
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	path := userdb.SocketPath(userdb.DefaultRunDir, userdb.ServiceName)
	_ = os.Remove(path)

	var config net.ListenConfig
	listener, err := config.Listen(ctx, "unix", path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // world-connectable, like the real socket
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	server := &userdb.Server{
		ServiceName: userdb.ServiceName,
		Source:      func() userdb.Source { return snapshot },
	}

	fmt.Println("serving", path)
	if err := server.Serve(ctx, listener); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// writeHostCertificate signs this container's SSH host key with a throwaway
// authority, using the same code path the server uses.
//
// The point is to hand a real OpenSSH client a certificate built by Cardinal
// rather than by ssh-keygen. A certificate that verifies against our own
// verifier proves nothing — that is exactly how CertChecker caught this project
// out once already.
func writeHostCertificate() error {
	_, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	caSigner, err := ssh.NewSignerFromKey(caPrivate)
	if err != nil {
		return err
	}

	hostKey, err := os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		return fmt.Errorf("reading the host key: %w", err)
	}
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(hostKey)
	if err != nil {
		return err
	}

	cert, err := sshca.SignHostCertificate(caSigner, sshca.HostRequest{
		HostID:     uuid.Nil,
		Name:       "cardinal-verify",
		PublicKey:  publicKey,
		Principals: []string{"cardinal-verify"},
	})
	if err != nil {
		return err
	}

	//nolint:gosec // sshd reads this as any user; it is a certificate, not a key
	if err := os.WriteFile("/etc/ssh/ssh_host_ed25519_key-cert.pub",
		ssh.MarshalAuthorizedKey(cert), 0o644); err != nil {
		return err
	}

	// The authority's public half, for the client's known_hosts. This is the one
	// line that replaces every fingerprint anybody would otherwise have accepted.
	//
	//nolint:gosec // a public key, in a container that exists for one command
	return os.WriteFile("/tmp/cardinal-ca.pub",
		ssh.MarshalAuthorizedKey(caSigner.PublicKey()), 0o644)
}
