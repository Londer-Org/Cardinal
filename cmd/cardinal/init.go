package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/directory/temporal"
	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/store"
)

// runInit performs first-run setup.
//
// The three commands it replaces were `user create`, `grant directory-admins`
// and `invite`, in that order, none of which a newcomer knows about — and a
// migrated database with no accounts is one nobody can sign in to, so the
// missing step is discovered as "why does nothing work" rather than as a
// missing step.
//
// Deliberately not part of `migrate`. Applying a schema is something you do to
// an existing deployment on every upgrade; creating an administrator is
// something you do once, and folding the two together would mean every upgrade
// carried code that can mint an administrator.
func runInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	display := fs.String("display", "", "the administrator's display name")
	policyPath := fs.String("policy", "policies/cardinal.cedar",
		"policy set to publish; empty to skip")
	baseURL := fs.String("url", "", "public base URL, if it differs from the config")
	configPath := fs.String("config", "", "configuration file")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal init <login>", errUsage)
	}
	login := pos[0]

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	// Refuse on a directory that already has administrators.
	//
	// A command that mints an administrator must not be runnable against a live
	// deployment by anyone who reaches the host — and "it only works when there
	// are none" is a condition that can be checked rather than remembered.
	admins, err := s.LookupEntity(ctx, directory.TypeGroup, "directory-admins")
	if err != nil {
		return errors.New("directory-admins is missing — run `cardinal migrate` first")
	}
	existing, err := s.MembersOfGroup(ctx, admins.ID)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		names := make([]string, 0, len(existing))
		for _, m := range existing {
			names = append(names, m.MemberName)
		}
		return fmt.Errorf(
			"this directory already has administrators (%s).\n"+
				"  init is for a fresh deployment. To add another, use:\n"+
				"    cardinal user create <login> && cardinal grant directory-admins <login>",
			strings.Join(names, ", "))
	}

	fmt.Fprintln(os.Stderr, "Setting up Cardinal.")
	fmt.Fprintln(os.Stderr)

	if *policyPath != "" {
		document, readErr := os.ReadFile(*policyPath)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", *policyPath, readErr)
		}
		// Validated before it is stored: publishing a policy set that does not
		// parse would leave the deployment default-deny with no obvious cause.
		if _, newEngineErr := policy.NewEngine(document, 0); newEngineErr != nil {
			return fmt.Errorf("%s does not parse: %w", *policyPath, newEngineErr)
		}
		version, readErr := s.PublishPolicy(ctx, string(document), "first-run default", nil)
		if readErr != nil {
			return fmt.Errorf("publishing policy: %w", readErr)
		}
		if readErr := s.ActivatePolicy(ctx, version.Version, nil); readErr != nil {
			return fmt.Errorf("activating policy: %w", readErr)
		}
		fmt.Fprintf(os.Stderr, "  policy set        version %d\n", version.Version)
	}

	entity, err := directory.NewEntity(directory.TypeUser, login, *display)
	if err != nil {
		return err
	}
	if createEntityErr := s.CreateEntity(ctx, entity, nil); createEntityErr != nil {
		if errors.Is(createEntityErr, directory.ErrAlreadyExists) {
			// The account may exist from a partial run. Continue rather than
			// making the operator work out which half succeeded.
			entity, createEntityErr = s.LookupEntity(ctx, directory.TypeUser, login)
			if createEntityErr != nil {
				return createEntityErr
			}
		} else {
			return createEntityErr
		}
	}
	fmt.Fprintf(os.Stderr, "  administrator     %s\n", entity.Name)

	// Granted by nobody: the CLI reaches the database directly and has no
	// authenticated operator behind it. Recording a subject who did not act
	// would make the audit trail worse than leaving it null.
	if grantErr := s.Grant(ctx, temporal.Grant{
		GroupID:   admins.ID,
		MemberID:  entity.ID,
		Period:    temporal.FromTime(time.Now()),
		GrantedBy: entity.ID,
		Reason:    "first-run setup",
	}, nil); grantErr != nil {
		return fmt.Errorf("granting directory-admins: %w", grantErr)
	}
	fmt.Fprintln(os.Stderr, "  group             directory-admins")

	issued, err := s.IssueInvitation(ctx, entity.ID, nil, store.InvitationTTL)
	if err != nil {
		return err
	}

	base := *baseURL
	if base == "" {
		if cfg, err := loadConfigForCheck(*configPath); err == nil {
			base = cfg.Server.PublicURL
		}
	}
	if base == "" {
		base = "http://localhost:8099"
		fmt.Fprintf(os.Stderr,
			"\n  Note: no public URL was readable, so the link below assumes %s.\n"+
				"  Pass -url if that is wrong.\n", base)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Start the server, then open this to register a passkey:")
	fmt.Fprintln(os.Stderr)

	// The link alone on stdout, so it pipes.
	fmt.Printf("%s/enroll?token=%s\n", strings.TrimRight(base, "/"), issued.Token)

	fmt.Fprintf(os.Stderr,
		"\n  Single use, expires in 24 hours. There is no password anywhere in\n"+
			"  this system: registering a passkey is how the account becomes usable.\n"+
			"  Register a second one afterwards — with only one, losing the device\n"+
			"  means losing the account.\n")
	return nil
}
