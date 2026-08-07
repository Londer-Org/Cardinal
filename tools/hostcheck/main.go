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
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/agent"
	"github.com/arthur-lonfils/cardinal/internal/sudoers"
	"github.com/arthur-lonfils/cardinal/internal/userdb"
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
