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

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/directory/temporal"
	"go.londer.be/cardinal/internal/store"
)

// open connects to the directory. Every command needs this and none should
// proceed without it, so failures here are fatal by design.
func open(ctx context.Context, dsnFlag string) (*store.Store, error) {
	s, err := store.Open(ctx, dsn(dsnFlag))
	if err != nil {
		return nil, err
	}
	return s, nil
}

// cliType maps a command word onto an entity type. The CLI uses hyphens where
// the database enum uses underscores, because hyphens read better in a shell.
func cliType(word string) directory.Type {
	return directory.Type(strings.ReplaceAll(word, "-", "_"))
}

func runEntityCommand(ctx context.Context, typeWord string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal %s <create|disable|enable> <name>", errUsage, typeWord)
	}

	// Disabling is the reversible way to cut somebody off — that is the whole
	// reason it exists rather than a delete — so both directions live here.
	switch args[0] {
	case "disable":
		return runEntityAvailability(ctx, typeWord, args[1:], false)
	case "enable":
		return runEntityAvailability(ctx, typeWord, args[1:], true)
	}

	if args[0] != "create" {
		return fmt.Errorf("%w: cardinal %s <create|disable|enable> <name>", errUsage, typeWord)
	}

	fs := flag.NewFlagSet(typeWord+" create", flag.ContinueOnError)
	display := fs.String("display", "", "human-friendly display name")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal %s create <name>", errUsage, typeWord)
	}
	name := pos[0]

	e, err := directory.NewEntity(cliType(typeWord), name, *display)
	if err != nil {
		return err
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	// actorID is nil: there is no authenticated administrator yet. Once
	// authentication lands (Phase 1) the CLI will present its own identity and
	// every audit event will name a real actor.
	if err := s.CreateEntity(ctx, e, nil); err != nil {
		return err
	}

	fmt.Printf("created %s %s\n  id %s\n", e.Type, e.Name, e.ID)
	return nil
}

func runList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	all := fs.Bool("all", false, "include disabled entities")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
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

	s, err := open(ctx, *dsnFlag)
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
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal show <type> <name>", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
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

func runGrant(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	forDur := fs.Duration("for", 0, "grant duration, e.g. 72h")
	until := fs.String("until", "", "end instant, RFC3339")
	reason := fs.String("reason", "", "why this access was granted")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal grant <group> <member>", errUsage)
	}
	if *forDur != 0 && *until != "" {
		return fmt.Errorf("%w: -for and -until are mutually exclusive", errUsage)
	}

	period := temporal.Forever()
	switch {
	case *forDur != 0:
		period = temporal.For(*forDur)
	case *until != "":
		t, parseErr := time.Parse(time.RFC3339, *until)
		if parseErr != nil {
			return fmt.Errorf("parsing -until: %w", parseErr)
		}
		period = temporal.Between(time.Now(), t)
	}
	if validateErr := period.Validate(); validateErr != nil {
		return validateErr
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	group, err := s.LookupEntity(ctx, directory.TypeGroup, pos[0])
	if err != nil {
		return err
	}
	member, err := resolveMember(ctx, s, pos[1])
	if err != nil {
		return err
	}

	// GrantedBy is the member until authentication exists; it becomes the
	// authenticated administrator in Phase 1.
	if err := s.Grant(ctx, temporal.Grant{
		GroupID:   group.ID,
		MemberID:  member.ID,
		Period:    period,
		GrantedBy: member.ID,
		Reason:    *reason,
	}, nil); err != nil {
		return err
	}

	fmt.Printf("granted %s %s membership of %s %s\n",
		member.Type, member.Name, group.Type, group.Name)
	if period.Until == nil {
		fmt.Printf("  period  from %s, no end\n", period.From.Format(time.RFC3339))
		fmt.Printf("  note    consider -for or -until; unbounded grants are the ones that get forgotten\n")
	} else {
		fmt.Printf("  period  %s\n", period)
	}
	return nil
}

func runRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	at := fs.String("at", "", "revocation instant, RFC3339 (default: now)")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal revoke <group> <member>", errUsage)
	}

	when := time.Now().UTC()
	if *at != "" {
		t, parseErr := time.Parse(time.RFC3339, *at)
		if parseErr != nil {
			return fmt.Errorf("parsing -at: %w", parseErr)
		}
		when = t
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	group, err := s.LookupEntity(ctx, directory.TypeGroup, pos[0])
	if err != nil {
		return err
	}
	member, err := resolveMember(ctx, s, pos[1])
	if err != nil {
		return err
	}

	if err := s.Revoke(ctx, group.ID, member.ID, when, nil); err != nil {
		return err
	}

	fmt.Printf("revoked %s %s from %s at %s\n",
		member.Type, member.Name, group.Name, when.Format(time.RFC3339))
	fmt.Printf("  the grant's history is preserved — see `cardinal history %s %s`\n",
		group.Name, member.Name)
	return nil
}

func runMembers(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("members", flag.ContinueOnError)
	at := fs.String("at", "", "instant to query, RFC3339 (default: now)")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal members <group>", errUsage)
	}

	when, err := parseInstant(*at)
	if err != nil {
		return err
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	group, err := s.LookupEntity(ctx, directory.TypeGroup, pos[0])
	if err != nil {
		return err
	}
	grants, err := s.DirectMembers(ctx, group.ID, when)
	if err != nil {
		return err
	}
	if len(grants) == 0 {
		fmt.Printf("%s has no members at %s\n", group.Name, instantLabel(*at, when))
		return nil
	}

	fmt.Printf("members of %s at %s\n", group.Name, instantLabel(*at, when))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  MEMBER\tPERIOD\tREASON") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, g := range grants {
		member, err := s.GetEntity(ctx, g.MemberID)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", member.Name, g.Period, g.Reason) //nolint:errcheck // the header is already written, so the status cannot be changed
	}
	return w.Flush()
}

func runMemberships(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("memberships", flag.ContinueOnError)
	at := fs.String("at", "", "instant to query, RFC3339 (default: now)")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal memberships <name>", errUsage)
	}

	when, err := parseInstant(*at)
	if err != nil {
		return err
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	member, err := resolveMember(ctx, s, pos[0])
	if err != nil {
		return err
	}
	memberships, err := s.ResolveMemberships(ctx, member.ID, when)
	if err != nil {
		return err
	}
	if len(memberships) == 0 {
		fmt.Printf("%s belongs to no groups at %s\n", member.Name, instantLabel(*at, when))
		return nil
	}

	fmt.Printf("%s belongs to, at %s\n", member.Name, instantLabel(*at, when))
	for _, m := range memberships {
		via := fmt.Sprintf("inherited, depth %d", m.Depth)
		if m.Direct() {
			via = "direct"
		}
		fmt.Printf("  %-24s %s\n", m.GroupName, via)
	}
	return nil
}

func runHistory(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal history <group> <member>", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	group, err := s.LookupEntity(ctx, directory.TypeGroup, pos[0])
	if err != nil {
		return err
	}
	member, err := resolveMember(ctx, s, pos[1])
	if err != nil {
		return err
	}

	grants, err := s.GrantHistory(ctx, group.ID, member.ID)
	if err != nil {
		return err
	}
	if len(grants) == 0 {
		fmt.Printf("%s has never been a member of %s\n", member.Name, group.Name)
		return nil
	}

	fmt.Printf("every grant of %s to %s\n", group.Name, member.Name)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  PERIOD\tACTIVE NOW\tREASON") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, g := range grants {
		active := "no"
		if g.Period.Active() {
			active = "yes"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", g.Period, active, g.Reason) //nolint:errcheck // the header is already written, so the status cannot be changed
	}
	return w.Flush()
}

// runRedact erases an entity's personal data for a GDPR Article 17 request.
func runRedact(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("redact", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal redact <type> <name>", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
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

	if err := s.RedactEntity(ctx, e.ID, nil); err != nil {
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
	pos, err := parse(fs, args[1:])
	if err != nil {
		return errUsage
	}
	if len(pos) > 0 {
		// Silently ignoring stray arguments hides typos, and a mistyped audit
		// command that appears to succeed is worse than one that fails.
		return fmt.Errorf("%w: audit verify takes no arguments, got %q", errUsage, pos[0])
	}

	s, err := open(ctx, *dsnFlag)
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

func parseInstant(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil // the zero time means "now" downstream
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing -at: %w", err)
	}
	return t, nil
}

func instantLabel(raw string, resolved time.Time) string {
	if raw == "" {
		return "now"
	}
	return resolved.Format(time.RFC3339)
}

// runEntityAvailability disables or re-enables an entity.
//
// One function for both because they are one decision made twice, and a pair of
// near-identical commands is how they drift — the first version of Cardinal had
// only the disabling half, which made "reversible" a claim rather than a fact.
func runEntityAvailability(ctx context.Context, typeWord string, args []string, enable bool) error {
	verb := "disable"
	if enable {
		verb = "enable"
	}

	fs := flag.NewFlagSet(typeWord+" "+verb, flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal %s %s <name>", errUsage, typeWord, verb)
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, cliType(typeWord), pos[0])
	if err != nil {
		return fmt.Errorf("no such %s %q", typeWord, pos[0])
	}

	if enable {
		if enableEntityErr := s.EnableEntity(ctx, entity.ID, nil); enableEntityErr != nil {
			return enableEntityErr
		}
		fmt.Printf("enabled %s %s\n", typeWord, entity.Name)
		fmt.Fprintln(os.Stderr,
			"\n  Sessions and access tokens were revoked when this was disabled and\n"+
				"  have not come back. Whoever this is signs in again.")
		return nil
	}

	if disableEntityErr := s.DisableEntity(ctx, entity.ID, nil); disableEntityErr != nil {
		return disableEntityErr
	}

	// Sessions and tokens, for the same reason the API does it: an account
	// disabled while its holder stays signed in is not disabled.
	sessions, err := s.RevokeAllSessions(ctx, entity.ID, nil)
	if err != nil {
		return err
	}
	tokens, err := s.RevokeAllAccessTokens(ctx, entity.ID)
	if err != nil {
		return err
	}

	fmt.Printf("disabled %s %s\n", typeWord, entity.Name)
	fmt.Printf("  revoked %d session(s) and %d access token(s)\n", sessions, tokens)
	fmt.Fprintf(os.Stderr,
		"\n  Reversible: `cardinal %s enable %s`. History and past grants are kept\n"+
			"  either way — nothing here is a delete.\n", typeWord, entity.Name)
	return nil
}
