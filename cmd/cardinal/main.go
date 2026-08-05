// Command cardinal is the administrative CLI for a Cardinal directory.
//
// It is deliberately built on the standard library's flag package rather than a
// CLI framework: Cardinal is security infrastructure, and every dependency is
// something to audit and keep patched. The ergonomics of a framework do not yet
// justify that cost.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const defaultDSN = "postgres://cardinal:cardinal@localhost:5433/cardinal?sslmode=disable"

func main() {
	// Cancel on SIGINT/SIGTERM so an interrupted command rolls its transaction
	// back rather than leaving one open until the connection is reaped.
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		// A bare errUsage means usage() was already printed; anything wrapping
		// it carries a specific message that must still reach the user.
		if !errors.Is(err, errBareUsage) {
			fmt.Fprintf(os.Stderr, "cardinal: %v\n", err)
		}
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

var (
	errUsage = errors.New("usage")
	// errBareUsage marks the case where full usage text has already been
	// printed, so main should not also print a one-line message.
	errBareUsage = fmt.Errorf("%w: printed", errUsage)
)

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return errBareUsage
	}

	cmd, rest := args[0], args[1:]

	switch cmd {
	case "user", "group", "host", "service-account", "application", "device", "role":
		return runEntityCommand(ctx, cmd, rest)
	case "list":
		return runList(ctx, rest)
	case "show":
		return runShow(ctx, rest)
	case "grant":
		return runGrant(ctx, rest)
	case "revoke":
		return runRevoke(ctx, rest)
	case "members":
		return runMembers(ctx, rest)
	case "memberships":
		return runMemberships(ctx, rest)
	case "history":
		return runHistory(ctx, rest)
	case "audit":
		return runAudit(ctx, rest)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "cardinal: unknown command %q\n\n", cmd)
		usage()
		return errBareUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cardinal — administer a Cardinal directory

USAGE
  cardinal <command> [arguments]

ENTITIES
  user create <name> [-display <text>]     Create a user
  group create <name> [-display <text>]    Create a group
  host create <name> [-display <text>]     Create a host
  list [type] [-all]                       List entities (-all includes disabled)
  show <type> <name>                       Show one entity and its memberships

MEMBERSHIP
  grant <group> <member> [flags]           Grant membership
      -for <duration>                        e.g. 72h — bounded, and preferred
      -until <RFC3339>                       explicit end instant
      -reason <text>                         why, preserved even after revocation
  revoke <group> <member> [-at <RFC3339>]  End a membership, keeping its history
  members <group> [-at <RFC3339>]          Who is in a group, now or at an instant
  memberships <user> [-at <RFC3339>]       Which groups someone is in, transitively
  history <group> <member>                 Every grant ever, including expired

AUDIT
  audit verify                             Verify the event log's hash chain

GLOBAL
  -dsn <url>    PostgreSQL connection string
                (or set CARDINAL_DSN; defaults to the local dev database)

Grants should normally be bounded. Whoever asks for access almost always knows
when they will stop needing it, and a bounded grant cannot be forgotten.
`)
}

// dsn resolves the connection string: flag, then environment, then the dev
// default. The dev default exists so the getting-started path is one command;
// it is not a credential anyone should ever see in production.
func dsn(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("CARDINAL_DSN"); env != "" {
		return env
	}
	return defaultDSN
}
