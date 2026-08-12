package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/store"
)

// `cardinal policy rule …` — policy without writing Cedar.
//
// The sentence policy exists to express is "these people may log into these
// machines", and until now saying it meant editing a file and republishing it.
// That is fine for the deployment that keeps its policy in git and reviews
// changes there, and wrong for everyone else — including anyone running the
// published image, where there is no file to edit.
//
// What this is not is a second source of truth. A rule added here becomes text
// in the same document, published as an ordinary version, activated the same
// way and rolled back the same way. Everything it does not recognise travels
// through untouched, comments included.

func runPolicyRule(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal policy rule <list|add|remove>", errUsage)
	}
	switch args[0] {
	case "list":
		return runPolicyRuleList(ctx, args[1:])
	case "add":
		return runPolicyRuleAdd(ctx, args[1:])
	case "remove":
		return runPolicyRuleRemove(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal policy rule <list|add|remove>", errUsage)
	}
}

// groupNames maps every group's identifier to its name.
//
// Policy stores identifiers because names are mutable (ADR 0002), and a person
// reading a rule wants the name. Resolving one way at the boundary is what lets
// both be true.
func groupNames(ctx context.Context, s *store.Store) map[string]string {
	out := map[string]string{}
	groups, err := s.ListEntities(ctx, directory.TypeGroup, true)
	if err != nil {
		// A listing that says `sre` is strictly better than one that says
		// 00000000-…-0e5be1, and a listing that fails entirely is worse than
		// either. The identifiers are still correct.
		return out
	}
	for _, g := range groups {
		out[g.ID.String()] = g.Name
	}
	return out
}

// named renders an identifier as its group name where one is known.
func named(names map[string]string, id string) string {
	if id == "" || id == policy.Everyone || id == policy.Anything {
		return id
	}
	if name, ok := names[id]; ok {
		return name
	}
	// Deliberately marked rather than printed bare. A rule naming a group that
	// is not there never matches, and Cedar being default-deny makes that look
	// exactly like the rule working.
	return id + " (missing)"
}

func runPolicyRuleList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy rule list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	active, err := s.ActivePolicy(ctx)
	if err != nil {
		return err
	}
	rules, err := policy.Parse(active.Document)
	if err != nil {
		return err
	}
	names := groupNames(ctx, s)

	fmt.Printf("policy version %d — %d rules\n\n", active.Version, len(rules))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RULE\tKIND\tWHAT IT SAYS") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, r := range rules {
		display := r
		display.PrincipalGroup = named(names, r.PrincipalGroup)
		display.ResourceGroup = named(names, r.ResourceGroup)

		kind := string(r.Kind)
		if r.Kind == policy.KindOther {
			kind = "hand-written"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.ID, kind, policy.Describe(display)) //nolint:errcheck // as above
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Print("\nHand-written rules are the forbids and the administration tiers.\n")
	fmt.Print("They are edited by publishing a policy file, so a guardrail is not\n")
	fmt.Print("removed with one command.\n")
	return nil
}

func runPolicyRuleAdd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal policy rule add "+
			"<web-access|application-access|ssh-login|run-as-root> <id> [flags]", errUsage)
	}
	kind := policy.RuleKind(args[0])

	fs := flag.NewFlagSet("policy rule add", flag.ContinueOnError)
	group := fs.String("group", "",
		"the group this applies to, by name; omit for anyone who signs in")
	resource := fs.String("to", "",
		"a group of applications or hosts, by name")
	app := fs.String("app", "", "one application, by name")
	anything := fs.Bool("anything", false,
		"every resource. Deliberate, loud, and rarely what you want")
	accounts := fs.String("account", "",
		"comma-separated local accounts for an SSH rule; the default is the "+
			"person's own login")
	stage := fs.Bool("stage", false,
		"publish without activating, to inspect it first")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := cli.Parse(fs, args[1:])
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: a rule needs an id, so a decision can name it", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	rule := policy.Rule{ID: pos[0], Kind: kind, PrincipalGroup: policy.Everyone}

	if *group != "" {
		principal, lookupErr := s.LookupEntity(ctx, directory.TypeGroup, *group)
		if lookupErr != nil {
			return fmt.Errorf("-group %s: %w", *group, lookupErr)
		}
		rule.PrincipalGroup = principal.ID.String()
	}

	switch {
	case *app != "":
		// Applications are named rather than identified, matching what the
		// decision points put in the request. Checked here so a typo is a
		// failed command rather than a rule that never matches.
		if _, lookupErr := s.LookupEntity(ctx, directory.TypeApplication, *app); lookupErr != nil {
			return fmt.Errorf("-app %s: %w", *app, lookupErr)
		}
		rule.ResourceApplication = *app
	case *resource != "":
		target, lookupErr := s.LookupEntity(ctx, directory.TypeGroup, *resource)
		if lookupErr != nil {
			return fmt.Errorf("-to %s: %w", *resource, lookupErr)
		}
		rule.ResourceGroup = target.ID.String()
	case *anything:
		rule.ResourceGroup = policy.Anything
	default:
		return fmt.Errorf("%w: pass -to <group>, -app <name>, or -anything", errUsage)
	}

	if *accounts != "" {
		for _, account := range strings.Split(*accounts, ",") {
			if account = strings.TrimSpace(account); account != "" {
				rule.LocalAccounts = append(rule.LocalAccounts, account)
			}
		}
	}

	active, err := s.ActivePolicy(ctx)
	if err != nil {
		return err
	}
	names := groupNames(ctx, s)
	display := rule
	display.PrincipalGroup = named(names, rule.PrincipalGroup)
	display.ResourceGroup = named(names, rule.ResourceGroup)

	// The comment names the groups; the rule names their identifiers. Both are
	// needed and for opposite reasons — the rule must not change meaning when
	// somebody renames a group, and the comment must be readable.
	rule.Comment = policy.Describe(display)

	updated, err := policy.Add(active.Document, rule)
	if err != nil {
		return err
	}

	return publishRuleChange(ctx, s, updated,
		"add rule "+rule.ID, policy.Describe(display), *stage)
}

func runPolicyRuleRemove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy rule remove", flag.ContinueOnError)
	stage := fs.Bool("stage", false, "publish without activating")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal policy rule remove <id>", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	active, err := s.ActivePolicy(ctx)
	if err != nil {
		return err
	}
	updated, err := policy.Remove(active.Document, pos[0])
	if err != nil {
		return err
	}

	return publishRuleChange(ctx, s, updated,
		"remove rule "+pos[0],
		pos[0]+" no longer applies.", *stage)
}

// publishRuleChange stores the edited document as a version, and activates it.
//
// Activating by default, unlike `cardinal policy publish`. The separation there
// exists so a hand-edited file can be inspected before it governs anything;
// here the change was described in the command that made it and the summary is
// printed back. What does not change is that this is an ordinary version:
// rollback is `cardinal policy activate <previous>`, and the line below says so
// because the moment to learn that is not during the incident.
func publishRuleChange(
	ctx context.Context, s *store.Store, document, description, summary string, stage bool,
) error {
	engine, err := policy.NewEngine([]byte(document), 0)
	if err != nil {
		return err
	}

	previous, err := s.ActivePolicy(ctx)
	if err != nil {
		return err
	}

	version, err := s.PublishPolicy(ctx, document, description, direct.ActorID())
	if err != nil {
		return err
	}

	fmt.Println(summary)
	fmt.Printf("  published version %d — %d rules\n",
		version.Version, len(engine.PolicyIDs()))

	// Reported before activation, and reported at all, because a rule naming a
	// group that is not there never matches — and Cedar being default-deny
	// makes that look exactly like the rule working.
	direct.WarnDangling(ctx, s, engine)

	if stage {
		fmt.Printf("  not yet live — activate with `cardinal policy activate %d`\n",
			version.Version)
		return nil
	}
	if err := s.ActivatePolicy(ctx, version.Version, direct.ActorID()); err != nil {
		return err
	}
	fmt.Printf("  live — every server picks this up within %s\n", policyReloadNotice)
	fmt.Printf("  undo with `cardinal policy activate %d`\n", previous.Version)
	return nil
}
