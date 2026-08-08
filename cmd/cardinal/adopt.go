package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/shadow"
	"go.londer.be/cardinal/internal/store"
)

// Adopting the numbers a fleet already uses.
//
// The answer to shadow mode's one blocking finding, and the reason that finding
// is not a dead end. A machine calling alice 1234 and Cardinal calling her
// 100003 has two resolutions: change every file on the machine, or change the
// row in Cardinal. The row is free while nothing has been told about it, and
// `find -uid 1234 -exec chown` is an evening.

// claim is every number the fleet proposes for one person.
//
// A map rather than a single number, so a disagreement is representable rather
// than something to detect afterwards. More than one entry cannot be satisfied
// and must not be resolved by picking.
type claim struct {
	numbers map[int][]string
}

func (c *claim) add(number int, host string) {
	if c.numbers == nil {
		c.numbers = map[int][]string{}
	}
	if !slices.Contains(c.numbers[number], host) {
		c.numbers[number] = append(c.numbers[number], host)
	}
}

func (c *claim) contested() bool { return len(c.numbers) > 1 }

// only returns the single proposed number. Meaningless when contested.
func (c *claim) only() (number int, hosts []string) {
	for n, h := range c.numbers {
		return n, h
	}
	return 0, nil
}

func (c *claim) describe() string {
	parts := make([]string, 0, len(c.numbers))
	for n, hosts := range c.numbers {
		parts = append(parts, fmt.Sprintf("%d on %s", n, strings.Join(hosts, ", ")))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func runAdopt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("posix adopt", flag.ContinueOnError)
	from := fs.String("from", "",
		"shadow report(s) to read, comma-separated; - for standard input")
	yes := fs.Bool("yes", false, "apply the changes rather than only showing them")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}

	// Two shapes: one person by hand, or a pile of reports collected from the
	// fleet. The second is the real one — the numbers live on the machines, and
	// asking an operator to retype them invites the typo that reattributes
	// somebody's home directory.
	claims := map[string]*claim{}

	switch {
	case *from != "" && len(pos) == 0:
		if err := readReports(*from, claims); err != nil {
			return err
		}
	case *from == "" && len(pos) == 2:
		number, err := strconv.Atoi(pos[1])
		if err != nil {
			return fmt.Errorf("%q is not a number", pos[1])
		}
		c := &claim{}
		c.add(number, "given on the command line")
		claims[pos[0]] = c
	default:
		return fmt.Errorf("%w: cardinal posix adopt <user> <number>\n"+
			"       cardinal posix adopt -from report.json[,report.json...]", errUsage)
	}

	if len(claims) == 0 {
		fmt.Println("nothing to adopt — no report named a number that disagrees")
		return nil
	}

	// Checked before anything is written, because a contradiction is not
	// something to discover halfway through.
	if err := refuseContradictions(claims); err != nil {
		return err
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	return applyClaims(ctx, s, claims, *yes)
}

// readReports collects the blocking uid findings from shadow reports.
//
// Only uid, deliberately. A gid finding on a user is about their private group,
// whose number follows the uid — adopting the uid settles it, and adopting them
// separately would let the two drift apart.
func readReports(list string, claims map[string]*claim) error {
	for path := range strings.SplitSeq(list, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		raw, err := readMaybeStdin(path)
		if err != nil {
			return err
		}

		var report shadow.Report
		if err := json.Unmarshal(raw, &report); err != nil {
			return fmt.Errorf("reading %s: %w — is this the output of "+
				"`cardinal-agent shadow -json`?", path, err)
		}

		host := report.Host
		if host == "" {
			host = path
		}

		for _, f := range report.Findings {
			if f.Severity != shadow.Blocking || f.What != "uid" {
				continue
			}
			number, err := strconv.Atoi(f.Local)
			if err != nil {
				return fmt.Errorf("%s: %s's current uid %q is not a number",
					path, f.User, f.Local)
			}

			if claims[f.User] == nil {
				claims[f.User] = &claim{}
			}
			claims[f.User].add(number, host)
		}
	}
	return nil
}

// refuseContradictions stops when the fleet does not agree with itself.
//
// Unsatisfiable rather than difficult: adopting either number reattributes that
// person's files on every machine using the other. The resolution is to make
// those machines agree first, which is work outside Cardinal.
func refuseContradictions(claims map[string]*claim) error {
	contested := make([]string, 0)
	for name, c := range claims {
		if c.contested() {
			contested = append(contested, name)
		}
	}
	if len(contested) == 0 {
		return nil
	}
	sort.Strings(contested)

	// Written to stdout with everything else. This command produces a report for
	// somebody to read top to bottom, and splitting it across two streams made
	// the advice appear above the lines it was about.
	fmt.Println("  These accounts have different numbers on different machines:")
	for _, name := range contested {
		fmt.Printf("    %-20s %s\n", name, claims[name].describe())
	}

	return fmt.Errorf(
		"%d account(s) cannot be satisfied by any single number.\n"+
			"  Reconcile those machines with each other first — adopting either number\n"+
			"  reattributes that person's files on the machines using the other",
		len(contested))
}

// applyClaims shows the changes, and makes them only when asked.
func applyClaims(ctx context.Context, s *store.Store, claims map[string]*claim, apply bool) error {
	names := make([]string, 0, len(claims))
	for name := range claims {
		names = append(names, name)
	}
	sort.Strings(names)

	var (
		changes int
		// Counted apart from other refusals, because the advice differs and
		// giving the wrong one is worse than giving none. "Already served" means
		// move the files; "no such user" means create them.
		served  int
		missing int
	)

	for _, name := range names {
		number, hosts := claims[name].only()

		entity, err := s.LookupEntity(ctx, directory.TypeUser, name)
		if err != nil {
			fmt.Printf("  %-20s no such user in the directory\n", name)
			missing++
			continue
		}

		current, err := s.POSIXIdentityFor(ctx, entity.ID)
		if err != nil {
			if errors.Is(err, store.ErrNoPOSIXIdentity) {
				fmt.Printf("  %-20s has no POSIX identity yet — run "+
					"`cardinal posix assign user %s` first\n", name, name)
				missing++
				continue
			}
			return err
		}

		if current.Number == number {
			continue
		}

		if !current.Adoptable() {
			fmt.Printf("  %-20s %d → %d  REFUSED: served to a host on %s\n",
				name, current.Number, number,
				current.FirstServedAt.UTC().Format("2006-01-02"))
			served++
			continue
		}

		fmt.Printf("  %-20s %d → %d  (%s)\n", name, current.Number, number,
			summarise(hosts))
		changes++

		if apply {
			if err := s.AdoptPOSIXNumber(ctx, entity.ID, number, nil); err != nil {
				return fmt.Errorf("adopting %s: %w", name, err)
			}
		}
	}

	fmt.Println()
	switch {
	case changes == 0 && served == 0 && missing == 0:
		fmt.Println("  Everything already agrees. Nothing to do.")
	case !apply:
		fmt.Printf("  %d change(s) would be made. Re-run with -yes to apply.\n", changes)
	default:
		fmt.Printf("  %d change(s) applied.\n", changes)
	}

	if served > 0 {
		fmt.Printf(
			"\n  %d already served to a host, so the number is on a filesystem\n"+
				"  somewhere and changing it now would reattribute files rather than\n"+
				"  edit a row. Those accounts need the other resolution: move the\n"+
				"  files with chown, on a quiet machine.\n", served)
	}
	if missing > 0 {
		fmt.Printf(
			"\n  %d named in a report and not in the directory. Create them first —\n"+
				"  a report describes machines, and Cardinal cannot adopt a number for\n"+
				"  somebody it has never heard of.\n", missing)
	}
	return nil
}

func summarise(hosts []string) string {
	if len(hosts) <= 1 {
		return strings.Join(hosts, "")
	}
	return fmt.Sprintf("%s and %d more", hosts[0], len(hosts)-1)
}

func readMaybeStdin(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // a path the operator named
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return raw, nil
}
