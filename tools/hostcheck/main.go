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
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/agent"
	"go.londer.be/cardinal/internal/shadow"
	"go.londer.be/cardinal/internal/sshca"
	"go.londer.be/cardinal/internal/sudoers"
	"go.londer.be/cardinal/internal/userdb"
	"golang.org/x/crypto/ssh"
)

func main() { os.Exit(main1()) }

// The shadow-mode half runs the comparison and exits, rather than serving
// anything. Same binary because it needs the same fixture.
var (
	shadowMode = flag.Bool("shadow", false, "run the shadow comparison and exit")
	expectName = flag.String("expect-name", "cardinalclash", "the account to compare")
	expectUID  = flag.Int("expect-uid", 100003, "the uid Cardinal would assign it")
)

func main1() int {
	flag.Parse()

	if *shadowMode {
		return runShadowCheck()
	}

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
	if installErr := sudoers.Install(ctx, sudoers.DefaultPath, content); installErr != nil {
		fmt.Fprintln(os.Stderr, installErr)
		return 1
	}

	if writeHostCertificateErr := writeHostCertificate(); writeHostCertificateErr != nil {
		fmt.Fprintln(os.Stderr, writeHostCertificateErr)
		return 1
	}

	if mkdirErr := os.MkdirAll(userdb.DefaultRunDir, 0o755); mkdirErr != nil { //nolint:gosec // matches systemd's own mode
		fmt.Fprintln(os.Stderr, mkdirErr)
		return 1
	}
	path := userdb.SocketPath(userdb.DefaultRunDir, userdb.ServiceName)
	_ = os.Remove(path) //nolint:errcheck // cleanup of a file the success path has already renamed away

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

// runShadowCheck compares a fixture against whatever the container's own NSS and
// sudo currently say, using the same code the agent runs.
func runShadowCheck() int {
	report, err := shadow.Compare(context.Background(), "verify", []shadow.Expected{{
		Name: *expectName, UID: *expectUID, GID: *expectUID,
		Home: "/home/" + *expectName, Shell: "/bin/bash",
	}}, nil, shadow.Local{})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	for _, f := range report.Findings {
		fmt.Printf("%s %s: now=%s cardinal=%s %s\n",
			f.User, f.What, f.Local, f.Cardinal, f.Severity)
	}
	return 0
}
