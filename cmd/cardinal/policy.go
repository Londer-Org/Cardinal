package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/policy"
)

func runPolicy(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal policy <publish|activate|list|test|show>", errUsage)
	}
	switch args[0] {
	case "publish":
		return runPolicyPublish(ctx, args[1:])
	case "activate":
		return runPolicyActivate(ctx, args[1:])
	case "list":
		return runPolicyList(ctx, args[1:])
	case "test":
		return runPolicyTest(args[1:])
	case "show":
		return runPolicyShow(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal policy <publish|activate|list|test|show>", errUsage)
	}
}

// runPolicyTest compiles a policy file without touching the database.
//
// Deliberately offline so it can run in CI, in a pre-commit hook, or on a
// laptop with no Cardinal to talk to. Catching a syntax error or a missing @id
// before publication is the whole point.
func runPolicyTest(args []string) error {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal policy test <file.cedar>", errUsage)
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
	return nil
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
	pos, err := parse(fs, args)
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

	s, err := open(ctx, *dsnFlag)
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
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal policy activate <version>", errUsage)
	}

	var version int64
	if _, err := fmt.Sscanf(pos[0], "%d", &version); err != nil {
		return fmt.Errorf("%w: version must be a number", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
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
	if _, err := policy.NewEngine([]byte(stored.Document), stored.Version); err != nil {
		return fmt.Errorf("version %d no longer compiles, so no server could "+
			"enforce it: %w", version, err)
	}

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
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
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
	fmt.Fprintln(w, "VERSION\tLIVE\tPUBLISHED\tDIGEST\tDESCRIPTION")
	for _, v := range versions {
		live := ""
		if v.Active() {
			live = "→ live"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			v.Version, live, v.CreatedAt.Format(time.DateOnly),
			hex.EncodeToString(v.Digest)[:12], v.Description)
	}
	return w.Flush()
}

func runPolicyShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("policy show", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
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
