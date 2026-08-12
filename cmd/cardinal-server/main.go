// Command cardinal-server runs Cardinal, and does the two things that have to
// happen against the database before anybody can sign in.
//
// It is a separate binary from `cardinal` so that the published image does not
// contain an administrative CLI. That distinction is not cosmetic: the image's
// entrypoint used to *be* the admin tool, and its configuration carries the
// connection string, so a shell in a running container was an unauthenticated
// administrator in one command with nothing to discover.
//
// What that buys, stated exactly: whoever holds the database credential still
// owns the directory, because psql exists and Cardinal cannot prevent it. This
// raises the cost from "type the command you already know" to "know the
// credential and bring a tool", and it stops the running server from being the
// tool. It is a smaller claim than it looks and it is the true one.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.londer.be/cardinal/internal/version"
)

func main() {
	// The signal context is torn down before exiting rather than by a defer,
	// which os.Exit would skip.
	os.Exit(start())
}

func start() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, errUsage) {
			usage()
			return 2
		}
		fmt.Fprintf(os.Stderr, "cardinal-server: %v\n", err)
		return 1
	}
	return 0
}

var errUsage = errors.New("usage")

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return errUsage
	}

	switch cmd, rest := args[0], args[1:]; cmd {
	case "serve":
		return runServe(ctx, rest)
	case "migrate":
		return runMigrate(ctx, rest)

	// First-run setup, and the one command here that mints an administrator.
	//
	// It stays in this binary because it runs before anything else can: a
	// migrated database with no accounts is one nobody can sign in to, and
	// discovering that as "why does nothing work" is worse than the cost of it
	// being here. Deliberately not part of `migrate`, so that an upgrade does
	// not carry it.
	case "init":
		return runInit(ctx, rest)

	case "config":
		return runConfig(ctx, rest)
	case "version":
		fmt.Println(version.String())
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("%w: unknown command %q", errUsage, cmd)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cardinal-server — run Cardinal

USAGE
  cardinal-server <command> [arguments]

  serve [-config <file>] [-dev]   Run the API and admin UI
  migrate [-status]               Apply the embedded schema
  init <login> [-display <text>]  First-run: policy, the first administrator,
                                  and an enrolment link
  config [-config <file>] [-all]  The effective configuration, and where each
                                  value came from
  version                         What this binary is

Administering a running Cardinal is the cardinal command, which signs in.
This binary holds only what has to reach the database before anybody can.
`)
}
