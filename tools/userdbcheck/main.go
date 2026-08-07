// Command userdbcheck serves a fixed set of records for verification against
// the real nss-systemd.
//
// It exists because the Go tests in internal/userdb prove only that the server
// agrees with a client written from the same reading of the specification. That
// is the trap this project has walked into before — a certificate that verifies
// against itself — so the provider is also checked with `getent`, which is the
// only client whose opinion matters.
//
// Run inside a container by `make verify-userdb`. Not shipped.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/arthur-lonfils/cardinal/internal/agent"
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
	snapshot := agent.NewSnapshot(&agent.Assignment{
		Host: "verify",
		Users: []agent.AssignedUser{{
			Name: "cardinaltest", UID: 100000, GID: 100000,
			Home: "/home/cardinaltest", Shell: "/bin/bash",
			Groups: []int{100001},
		}},
		Groups: []agent.AssignedGroup{{
			Name: "cardinalsre", GID: 100001, Members: []string{"cardinaltest"},
		}},
	})

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
