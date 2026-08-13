package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/api"
)

// POSIX identity, through the API.

// POSIX dispatches `cardinal posix`.
func POSIX(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal posix <assign|show|set|list|adopt>", cli.ErrUsage)
	}

	switch args[0] {
	case "assign":
		return posixAssign(ctx, server, flow, args[1:])
	case "show":
		return posixShow(ctx, server, flow, args[1:])
	case "set":
		return posixSet(ctx, server, flow, args[1:])
	case "list":
		return posixList(ctx, server, flow, args[1:])
	case "adopt":
		return Adopt(ctx, server, flow, args[1:])
	default:
		return fmt.Errorf("%w: cardinal posix <assign|show|set|list|adopt>", cli.ErrUsage)
	}
}

// posixKind reads the word a caller typed for what they are addressing.
//
// The allocation range is not a flag here and never was. Two operators running
// assign with different ranges would produce numbers from two of them in one
// directory, and the damage would not show until something collided — so the
// server's configuration decides, which is also now the only copy of it.
func posixKind(word string) (string, error) {
	switch word {
	case "user", "group":
		return word, nil
	default:
		return "", fmt.Errorf("%w: the type is `user` or `group`, not %q", cli.ErrUsage, word)
	}
}

func posixAssign(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("posix assign", flag.ContinueOnError)
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal posix assign <user|group> <name>", cli.ErrUsage)
	}
	kind, err := posixKind(pos[0])
	if err != nil {
		return err
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	var identity api.POSIXIdentity
	if kind == "group" {
		identity, err = client.AssignGroupPOSIX(ctx, pos[1])
	} else {
		identity, err = client.AssignPOSIX(ctx, pos[1], api.POSIXRequest{})
	}
	if err != nil {
		return err
	}

	label := "uid"
	if kind == "group" {
		label = "gid"
	}
	fmt.Printf("%s %s = %d\n", pos[1], label, identity.Number)
	if kind == "user" {
		fmt.Printf("  home   %s\n", identity.HomeDirectory)
		fmt.Printf("  shell  %s\n", identity.LoginShell)
		// The user-private group: same name, same number, and stored nowhere.
		// The convention is that every user has one, so there is nothing to
		// record and nothing to ask the server for — the agent synthesises it
		// on each host the same way.
		fmt.Printf("  group  %s (%d), synthesised — not a directory group\n",
			pos[1], identity.Number)
	}

	fmt.Println()
	if kind == "group" {
		fmt.Println("  Files owned by this group will record the number, not the name.")
	} else {
		fmt.Println("  Every file this account creates will record the number, not the name.")
	}
	// Precise about when it becomes permanent, because that is the fact
	// somebody planning a migration needs.
	fmt.Println("  It can still be changed with `cardinal posix adopt` — until the first")
	fmt.Println("  host is told about it, after which it is on a filesystem somewhere and")
	fmt.Println("  changing it would move files rather than edit a row.")
	return nil
}

func posixShow(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("posix show", flag.ContinueOnError)
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal posix show <user|group> <name>", cli.ErrUsage)
	}
	kind, err := posixKind(pos[0])
	if err != nil {
		return err
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	var (
		identity api.POSIXIdentity
		has      bool
	)
	if kind == "group" {
		identity, has, err = client.GroupPOSIX(ctx, pos[1])
	} else {
		identity, has, err = client.UserPOSIX(ctx, pos[1])
	}
	if err != nil {
		return err
	}
	if !has {
		return fmt.Errorf("%s has no POSIX identity — assign one with "+
			"`cardinal posix assign %s %s`", pos[1], kind, pos[1])
	}

	if kind == "group" {
		fmt.Printf("%s:x:%d:\n", pos[1], identity.Number)
		return nil
	}

	// The passwd line itself, because that is the thing an operator is trying
	// to predict when they run this. The GECOS field is left empty rather than
	// filled with a display name: it is world-readable on every host, and a
	// real name is exactly the sort of thing that should not be.
	fmt.Printf("%s:x:%d:%d::%s:%s\n", pos[1], identity.Number, identity.Number,
		identity.HomeDirectory, identity.LoginShell)
	return nil
}

func posixSet(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("posix set", flag.ContinueOnError)
	home := fs.String("home", "", "home directory")
	shell := fs.String("shell", "", "login shell")
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal posix set <user> [-home <path>] [-shell <path>]",
			cli.ErrUsage)
	}
	if *home == "" && *shell == "" {
		return fmt.Errorf("%w: give -home, -shell, or both", cli.ErrUsage)
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	// Unset means unchanged, not empty. Two settings behind one command, and a
	// command that silently blanked the one you did not mention would be a way
	// to give somebody a login shell of "". The server keeps the same rule, so
	// only what was asked for is sent.
	var req api.POSIXRequest
	if *home != "" {
		req.HomeDirectory = home
	}
	if *shell != "" {
		req.LoginShell = shell
	}

	identity, err := client.AssignPOSIX(ctx, pos[0], req)
	if err != nil {
		return err
	}

	fmt.Printf("%s:x:%d:%d::%s:%s\n", pos[0], identity.Number, identity.Number,
		identity.HomeDirectory, identity.LoginShell)
	fmt.Fprintln(os.Stderr,
		"\n  Takes effect when each host's agent next refreshes. Existing files keep\n"+
			"  their owner, because the uid has not changed — moving the home directory\n"+
			"  itself is a job for the machine, not for Cardinal.")
	return nil
}

func posixList(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("posix list", flag.ContinueOnError)
	if _, err := parse(fs, args); err != nil {
		return cli.ErrUsage
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	identities, err := client.POSIXIdentities(ctx)
	if err != nil {
		return err
	}
	if len(identities) == 0 {
		fmt.Println("nobody has a POSIX identity yet — assign one with `cardinal posix assign`")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NUMBER\tTYPE\tNAME\tHOME\tSHELL\tSTATE") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, p := range identities {
		home, shell := p.HomeDirectory, p.LoginShell
		if home == "" {
			home, shell = "—", "—"
		}
		// Whether it can still be adopted, which is the one thing about a
		// number that changes over its life and the thing a migration turns on.
		state := "served"
		if p.Adoptable {
			state = "adoptable"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck // the header is already written, so the status cannot be changed
			p.Number, p.Type, p.Name, home, shell, state)
	}
	return w.Flush()
}
