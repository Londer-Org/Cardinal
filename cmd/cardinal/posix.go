package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/directory/posix"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

func runPOSIX(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal posix <assign|show|set|list|adopt>", errUsage)
	}
	switch args[0] {
	case "assign":
		return runPOSIXAssign(ctx, args[1:])
	case "show":
		return runPOSIXShow(ctx, args[1:])
	case "set":
		return runPOSIXSet(ctx, args[1:])
	case "list":
		return runPOSIXList(ctx, args[1:])
	case "adopt":
		return runAdopt(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal posix <assign|show|set|list|adopt>", errUsage)
	}
}

// posixRange resolves the allocation range from configuration.
//
// Read from the config file rather than a flag, and deliberately so. Two
// operators running `assign` with different flags would produce numbers from
// two ranges in one directory, and the damage would not be visible until
// something collided.
func posixRange(configPath string) posix.Range {
	cfg, err := direct.LoadConfig(configPath)
	if err != nil {
		// Unreadable configuration is not an error here. It is the normal case
		// for a CLI run against a development database, and Effective() would
		// return the same default the server uses, so the numbers agree either
		// way.
		return posix.DefaultRange
	}
	return cfg.POSIX.Effective()
}

func runPOSIXAssign(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("posix assign", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	configPath := fs.String("config", "", "configuration file, for the id range")

	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal posix assign <user|group> <name>", errUsage)
	}

	typ, err := posixType(pos[0])
	if err != nil {
		return err
	}

	idRange := posixRange(*configPath)

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, typ, pos[1])
	if err != nil {
		return fmt.Errorf("no such %s %q", pos[0], pos[1])
	}

	identity, err := s.AssignPOSIXIdentity(ctx, entity.ID, idRange, direct.ActorID())
	if err != nil {
		if errors.Is(err, store.ErrPOSIXRangeExhausted) {
			fmt.Fprintln(os.Stderr,
				"\n  Raise posix.range_high. Numbers already handed out are never\n"+
					"  reused, so widening the range is safe and narrowing it is not.")
			return err
		}
		return err
	}

	label := "uid"
	if typ == directory.TypeGroup {
		label = "gid"
	}

	fmt.Printf("%s %s = %d\n", entity.Name, label, identity.Number)
	if typ == directory.TypeUser {
		fmt.Printf("  home   %s\n", identity.HomeDirectory)
		fmt.Printf("  shell  %s\n", identity.LoginShell)
		name, gid := identity.PrimaryGroup()
		fmt.Printf("  group  %s (%d), synthesised — not a directory group\n", name, gid)
	}
	fmt.Println()
	if typ == directory.TypeGroup {
		fmt.Println("  Files owned by this group will record the number, not the name.")
	} else {
		fmt.Println("  Every file this account creates will record the number, not the name.")
	}
	// Precise about when it becomes permanent, because that is the fact somebody
	// planning a migration needs. It said "permanent, no command to change it",
	// which was true before `posix adopt` existed and is not any more.
	fmt.Println("  It can still be changed with `cardinal posix adopt` — until the first")
	fmt.Println("  host is told about it, after which it is on a filesystem somewhere and")
	fmt.Println("  changing it would move files rather than edit a row.")
	return nil
}

func runPOSIXShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("posix show", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal posix show <user|group> <name>", errUsage)
	}

	typ, err := posixType(pos[0])
	if err != nil {
		return err
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, typ, pos[1])
	if err != nil {
		return fmt.Errorf("no such %s %q", pos[0], pos[1])
	}

	identity, err := s.POSIXIdentityFor(ctx, entity.ID)
	if err != nil {
		if errors.Is(err, store.ErrNoPOSIXIdentity) {
			return fmt.Errorf("%s has no POSIX identity — assign one with "+
				"`cardinal posix assign %s %s`", entity.Name, pos[0], entity.Name)
		}
		return err
	}

	if typ == directory.TypeGroup {
		fmt.Printf("%s:x:%d:\n", identity.Name, identity.Number)
		return nil
	}

	// The passwd line itself, because that is the thing an operator is trying
	// to predict when they run this. The GECOS field is left empty rather than
	// filled with a display name: it is world-readable on every host, and a
	// real name is exactly the sort of thing that should not be.
	fmt.Printf("%s:x:%d:%d::%s:%s\n", identity.Name, identity.Number,
		identity.Number, identity.HomeDirectory, identity.LoginShell)
	return nil
}

func runPOSIXSet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("posix set", flag.ContinueOnError)
	home := fs.String("home", "", "home directory")
	shell := fs.String("shell", "", "login shell")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal posix set <user> [-home <path>] [-shell <path>]", errUsage)
	}
	if *home == "" && *shell == "" {
		return fmt.Errorf("%w: give -home, -shell, or both", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, directory.TypeUser, pos[0])
	if err != nil {
		return fmt.Errorf("no such user %q", pos[0])
	}

	current, err := s.POSIXIdentityFor(ctx, entity.ID)
	if err != nil {
		if errors.Is(err, store.ErrNoPOSIXIdentity) {
			return fmt.Errorf("%s has no POSIX identity — assign one with "+
				"`cardinal posix assign user %s`", entity.Name, entity.Name)
		}
		return err
	}

	// Unset means unchanged, not empty. Two settings behind one command, and a
	// command that silently blanked the one you did not mention would be a way
	// to give somebody a login shell of "".
	if *home == "" {
		*home = current.HomeDirectory
	}
	if *shell == "" {
		*shell = current.LoginShell
	}

	if err := s.SetPOSIXAttributes(ctx, entity.ID, *home, *shell, direct.ActorID()); err != nil {
		return err
	}

	fmt.Printf("%s:x:%d:%d::%s:%s\n", entity.Name, current.Number, current.Number, *home, *shell)
	fmt.Fprintln(os.Stderr,
		"\n  Takes effect when each host's agent next refreshes. Existing files keep\n"+
			"  their owner, because the uid has not changed — moving the home directory\n"+
			"  itself is a job for the machine, not for Cardinal.")
	return nil
}

func runPOSIXList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("posix list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	identities, err := s.ListPOSIXIdentities(ctx)
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
		if p.Adoptable() {
			state = "adoptable"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck // the header is already written, so the status cannot be changed
			p.Number, p.Type, p.Name, home, shell, state)
	}
	return w.Flush()
}

func posixType(word string) (directory.Type, error) {
	switch word {
	case "user":
		return directory.TypeUser, nil
	case "group":
		return directory.TypeGroup, nil
	default:
		return "", fmt.Errorf(
			"%q is not a POSIX-capable type — only users and groups have numbers", word)
	}
}
