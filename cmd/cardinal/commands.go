package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// open connects to the directory. Every command needs this and none should
// proceed without it, so failures here are fatal by design.

// cliType turns the word somebody types into the type stored in the database.
// The CLI spells service_account with a hyphen, because a command line does.
func cliType(word string) directory.Type {
	return directory.Type(strings.ReplaceAll(word, "-", "_"))
}

func runList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	all := fs.Bool("all", false, "include disabled entities")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}

	var typ directory.Type
	if len(pos) > 0 {
		typ = cliType(pos[0])
		if !typ.Valid() {
			return fmt.Errorf("%w: %q", directory.ErrInvalidType, pos[0])
		}
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entities, err := s.ListEntities(ctx, typ, *all)
	if err != nil {
		return err
	}
	if len(entities) == 0 {
		fmt.Println("no entities")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tNAME\tID\tSTATUS") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, e := range entities {
		status := "active"
		if !e.Active() {
			status = "disabled " + e.DisabledAt.Format(time.DateOnly)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Type, e.Name, e.ID, status) //nolint:errcheck // the header is already written, so the status cannot be changed
	}
	return w.Flush()
}

func runShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal show <type> <name>", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	e, err := s.LookupEntity(ctx, cliType(pos[0]), pos[1])
	if err != nil {
		return err
	}

	fmt.Printf("%s %s\n", e.Type, e.Name)
	fmt.Printf("  id           %s\n", e.ID)
	if e.DisplayName != "" {
		fmt.Printf("  display      %s\n", e.DisplayName)
	}
	fmt.Printf("  created      %s\n", e.CreatedAt.Format(time.RFC3339))
	if !e.Active() {
		fmt.Printf("  disabled     %s\n", e.DisabledAt.Format(time.RFC3339))
	}

	memberships, err := s.ResolveMemberships(ctx, e.ID, time.Time{})
	if err != nil {
		return err
	}
	if len(memberships) > 0 {
		fmt.Printf("  memberships\n")
		for _, m := range memberships {
			via := fmt.Sprintf("inherited, depth %d", m.Depth)
			if m.Direct() {
				via = "direct"
			}
			fmt.Printf("    %-24s %s\n", m.GroupName, via)
		}
	}
	return nil
}

// runRedact erases an entity's personal data for a GDPR Article 17 request.
func runRedact(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("redact", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal redact <type> <name>", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	e, err := s.LookupEntity(ctx, cliType(pos[0]), pos[1])
	if err != nil {
		return err
	}

	if !*yes {
		// Irreversible by design — a reversible erasure is not an erasure — so
		// the operator states the name back rather than pressing y.
		fmt.Printf("This permanently erases the personal data of %s %s (%s).\n",
			e.Type, e.Name, e.ID)
		fmt.Printf("Name, display name and attributes are destroyed; grant\n")
		fmt.Printf("justifications are cleared; sessions are deleted. Membership\n")
		fmt.Printf("periods and the audit chain are preserved, but will no longer\n")
		fmt.Printf("be attributable to anyone. This cannot be undone.\n\n")
		fmt.Printf("Type the name %q to confirm: ", e.Name)

		var typed string
		if _, err := fmt.Scanln(&typed); err != nil || typed != e.Name {
			fmt.Println("aborted")
			return nil
		}
	}

	if err := s.RedactEntity(ctx, e.ID, direct.ActorID()); err != nil {
		return err
	}

	fmt.Printf("erased personal data for %s\n", e.ID)
	fmt.Printf("  membership history and the audit chain are intact\n")
	fmt.Printf("  verify with `cardinal audit verify`\n")
	return nil
}

func runAudit(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("%w: cardinal audit verify", errUsage)
	}

	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args[1:])
	if err != nil {
		return errUsage
	}
	if len(pos) > 0 {
		// Silently ignoring stray arguments hides typos, and a mistyped audit
		// command that appears to succeed is worse than one that fails.
		return fmt.Errorf("%w: audit verify takes no arguments, got %q", errUsage, pos[0])
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	report, err := s.ValidateChain(ctx)
	if err != nil {
		return err
	}

	if !report.Valid {
		// This is a security incident, not a data-quality problem: the journal
		// is append-only and rule-protected, so a broken chain means something
		// bypassed the database's normal write path.
		fmt.Fprintf(os.Stderr, "AUDIT CHAIN BROKEN at event %d\n  %s\n\n",
			report.BrokenAtSeq, report.Reason)
		fmt.Fprintf(os.Stderr,
			"The event log is append-only and protected by database rules, so this\n"+
				"indicates direct database access outside the application. Treat it as\n"+
				"a security incident.\n")
		return errors.New("audit chain verification failed")
	}

	fmt.Printf("audit chain intact — %d events verified\n", report.EventsChecked)
	return nil
}

// resolveMember finds an entity by name across the types that can hold
// membership, so `cardinal grant engineers alice` works without making the
// caller state that alice is a user.
func resolveMember(ctx context.Context, s *store.Store, name string) (*directory.Entity, error) {
	for _, t := range []directory.Type{
		directory.TypeUser, directory.TypeGroup, directory.TypeHost,
		directory.TypeServiceAccount, directory.TypeApplication,
		directory.TypeDevice, directory.TypeRole,
	} {
		e, err := s.LookupEntity(ctx, t, name)
		if err == nil {
			return e, nil
		}
	}
	return nil, fmt.Errorf("%w: no entity named %q", directory.ErrNotFound, name)
}
