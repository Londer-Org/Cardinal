package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/server/policy"
)

func runPolicy(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal policy <publish|activate|list|test|show|rule>", errUsage)
	}
	switch args[0] {
	case "publish":
		return runPolicyPublish(ctx, args[1:])
	case "activate":
		return runPolicyActivate(ctx, args[1:])
	case "list":
		return runPolicyList(ctx, args[1:])
	case "test":
		return runPolicyTest(ctx, args[1:])
	case "show":
		return runPolicyShow(ctx, args[1:])
	case "rule":
		return runPolicyRule(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal policy <publish|activate|list|test|show|rule>", errUsage)
	}
}

// runPolicyTest compiles a policy file, and checks what it names if it can.
//
// Compilation is deliberately offline so it runs in CI, in a pre-commit hook,
// or on a laptop with no Cardinal to talk to. Catching a syntax error or a
// missing @id before publication is the whole point.
//
// Whether the groups and applications a rule names actually exist is a question
// only a directory can answer, so it needs -dsn. It is not run silently when
// one is not given: a check that quietly did not happen is worse than one that
// is missing, because the clean output reads as a clean bill of health.
func runPolicyTest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "",
		"PostgreSQL connection string; enables the check for groups and "+
			"applications a rule names but that do not exist")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal policy test <file.cedar> [-dsn <url>]", errUsage)
	}

	document, err := os.ReadFile(pos[0]) //nolint:gosec // operator-supplied path, by design
	if err != nil {
		return fmt.Errorf("reading policy: %w", err)
	}

	engine, err := policy.NewEngine(document, 0)
	if err != nil {
		return err
	}

	names := engine.PolicyIDs()
	fmt.Printf("%s is valid — %d policies\n", pos[0], len(names))
	for _, name := range names {
		fmt.Printf("  %s\n", name)
	}

	if *dsnFlag == "" {
		fmt.Printf("\nnot checked: whether the groups and applications these rules " +
			"name exist.\n  Pass -dsn to check. A rule naming a group that is not " +
			"there never matches,\n  and Cedar being default-deny makes that look " +
			"like the rule working.\n")
		return nil
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	dangling, err := engine.Dangling(ctx, s.PolicyReferenceExists)
	if err != nil {
		return err
	}
	if len(dangling) == 0 {
		fmt.Printf("\nevery group and application these rules name exists\n")
		return nil
	}

	// Reported on stderr and as a failure, because this is the one command
	// whose entire job is to find this before it is published.
	fmt.Fprintf(os.Stderr, "\n%s", policy.ExplainDangling(dangling))
	return fmt.Errorf("%s names %d entities that do not exist", pos[0], len(dangling))
}

// policyReloadNotice matches watchPolicy's interval in serve.go.
//
// Duplicated as a string rather than imported, because the two live in the same
// package and the number is only ever shown to a person — but if that interval
// changes, this is the line that starts lying.
const policyReloadNotice = "ten seconds"

func runPolicyPublish(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy publish", flag.ContinueOnError)
	description := fs.String("description", "", "what changed and why")
	activate := fs.Bool("activate", false, "make this version live immediately")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal policy publish <file.cedar> [-activate]", errUsage)
	}

	document, err := os.ReadFile(pos[0]) //nolint:gosec // operator-supplied path, by design
	if err != nil {
		return fmt.Errorf("reading policy: %w", err)
	}

	// Compile before storing. Publishing something that cannot load would leave
	// a version in the database that no server can activate.
	engine, err := policy.NewEngine(document, 0)
	if err != nil {
		return err
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	version, err := s.PublishPolicy(ctx, string(document), *description, nil)
	if err != nil {
		return err
	}

	fmt.Printf("published version %d — %d policies\n", version.Version, len(engine.PolicyIDs()))
	fmt.Printf("  digest %s\n", hex.EncodeToString(version.Digest))

	direct.WarnDangling(ctx, s, engine)

	if !*activate {
		// Publish and activate are separate so a version can be inspected
		// before it governs anything.
		fmt.Printf("  not yet live — activate with `cardinal policy activate %d`\n",
			version.Version)
		return nil
	}

	if err := s.ActivatePolicy(ctx, version.Version, nil); err != nil {
		return err
	}
	// This used to say "restart the server, or it keeps serving the previous
	// set", which was true and is no longer: every node checks the activated
	// version on a short interval and swaps its engine. The old wording made
	// rolling back a two-step operation whose second step needed a shell, which
	// is the wrong shape for the one policy action people take in a hurry.
	fmt.Printf("  activated — every server picks this up within %s\n",
		policyReloadNotice)
	return nil
}

func runPolicyActivate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy activate", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal policy activate <version>", errUsage)
	}

	var version int64
	if _, sscanfErr := fmt.Sscanf(pos[0], "%d", &version); sscanfErr != nil {
		return fmt.Errorf("%w: version must be a number", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	// Compiled before anything is written, which the API path also does.
	//
	// A version that no longer compiles cannot be loaded by any node, and each
	// one keeps serving whatever it already had — so activating one leaves the
	// fleet split across policy sets with nothing on screen to say so, and the
	// only symptom is that a change did not take effect. Refusing here turns
	// that into a failed command.
	stored, err := s.PolicyVersionByNumber(ctx, version)
	if err != nil {
		return err
	}
	engine, err := policy.NewEngine([]byte(stored.Document), stored.Version)
	if err != nil {
		return fmt.Errorf("version %d no longer compiles, so no server could "+
			"enforce it: %w", version, err)
	}

	// Before activating, not after: rolling back to a version that names a
	// group somebody has since deleted is a plausible way to reach for the
	// rollback and find it did not restore what it looked like it would.
	direct.WarnDangling(ctx, s, engine)

	if err := s.ActivatePolicy(ctx, version, nil); err != nil {
		return err
	}
	fmt.Printf("version %d is now live\n", version)
	fmt.Printf("  every server picks this up within %s\n", policyReloadNotice)
	fmt.Printf("  rollback is the same command with an earlier version\n")
	return nil
}

func runPolicyList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	versions, err := s.ListPolicyVersions(ctx, 20)
	if err != nil {
		return err
	}
	if len(versions) == 0 {
		fmt.Println("no policy versions published")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "VERSION\tLIVE\tPUBLISHED\tDIGEST\tDESCRIPTION") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, v := range versions {
		live := ""
		if v.Active() {
			live = "→ live"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", //nolint:errcheck // the header is already written, so the status cannot be changed
			v.Version, live, v.CreatedAt.Format(time.DateOnly),
			hex.EncodeToString(v.Digest)[:12], v.Description)
	}
	return w.Flush()
}

func runPolicyShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy show", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	version, err := s.ActivePolicy(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("version %d, live since %s\n", version.Version,
		version.ActivatedAt.Format(time.RFC3339))
	fmt.Printf("digest %s\n\n", hex.EncodeToString(version.Digest))
	fmt.Print(version.Document)
	return nil
}
