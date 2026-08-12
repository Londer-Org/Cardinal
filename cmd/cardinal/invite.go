package main

import (
	"context"
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

func runInvite(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal invite <login>|list|revoke <login>", errUsage)
	}
	switch args[0] {
	case "list":
		return runInviteList(ctx, args[1:])
	case "revoke":
		return runInviteRevoke(ctx, args[1:])
	default:
		return runInviteIssue(ctx, args)
	}
}

// runInviteIssue prints an enrollment link.
//
// The link is printed to stdout and nothing else, so it can be piped. Everything
// explanatory goes to stderr — including the warning below, which must not be
// silently lost when someone redirects the useful part into a message.
func runInviteIssue(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	ttl := fs.Duration("for", store.InvitationTTL,
		"how long the invitation stays usable")
	baseURL := fs.String("url", "",
		"public base URL of this Cardinal, if it differs from the config")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	configPath := fs.String("config", "", "configuration file, for the public URL")

	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal invite <login>", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, directory.TypeUser, pos[0])
	if err != nil {
		return fmt.Errorf("no such user %q — create it first with `cardinal user create %s`",
			pos[0], pos[0])
	}

	recovery, err := s.HasCredentials(ctx, entity.ID)
	if err != nil {
		return err
	}

	// Issued by nobody: the CLI reaches the database directly and has no
	// authenticated operator behind it. That is honest rather than convenient —
	// recording a subject who did not act would make the audit trail worse than
	// leaving it null.
	issued, err := s.IssueInvitation(ctx, entity.ID, nil, *ttl)
	if err != nil {
		return err
	}

	base := *baseURL
	if base == "" {
		if cfg, err := direct.LoadConfig(*configPath); err == nil {
			base = cfg.Server.PublicURL
		}
	}
	if base == "" {
		base = "http://localhost:8099"
		fmt.Fprintf(os.Stderr,
			"  Note: no public URL was readable, so the link below assumes %s.\n"+
				"  Pass -url if that is wrong.\n\n", base)
	}

	if recovery {
		fmt.Fprintf(os.Stderr,
			"  WARNING: %s already has a passkey. This link lets whoever holds it\n"+
				"  register another one on that account, which is how a lost-device\n"+
				"  recovery works and also what an account takeover looks like.\n\n",
			entity.Name)
	}

	fmt.Fprintf(os.Stderr, "  invitation for %s, valid until %s\n\n",
		entity.Name, issued.Invitation.ExpiresAt.Local().Format(time.RFC1123))

	fmt.Printf("%s/enroll?token=%s\n", strings.TrimRight(base, "/"), issued.Token)

	fmt.Fprintf(os.Stderr,
		"\n  Single use. It grants no session and cannot administer anything —\n"+
			"  the holder can register one passkey on this account and nothing else.\n"+
			"  Safe to send over chat or email; revoke with `cardinal invite revoke %s`.\n",
		entity.Name)
	return nil
}

func runInviteList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("invite list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	invitations, err := s.PendingInvitations(ctx)
	if err != nil {
		return err
	}
	if len(invitations) == 0 {
		fmt.Println("no outstanding invitations")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LOGIN\tEXPIRES\tREMAINING") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, inv := range invitations {
		remaining := time.Until(inv.ExpiresAt).Round(time.Minute)
		fmt.Fprintf(w, "%s\t%s\t%s\n", inv.Login, //nolint:errcheck // the header is already written, so the status cannot be changed
			inv.ExpiresAt.Local().Format(time.RFC3339), remaining)
	}
	return w.Flush()
}

func runInviteRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("invite revoke", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal invite revoke <login>", errUsage)
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
	if err := s.RevokeInvitation(ctx, entity.ID, nil); err != nil {
		return err
	}

	fmt.Printf("revoked the outstanding invitation for %s\n", entity.Name)
	return nil
}
