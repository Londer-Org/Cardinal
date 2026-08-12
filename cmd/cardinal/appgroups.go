package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

// `cardinal app groups …` — how much of the directory an application is told.
//
// The forwardAuth header and the OIDC groups claim carried every group a person
// belonged to, so an internal wiki learned somebody was in hr-investigations.
// ADR 0032 is the argument; this is the administration.
//
// Nothing here changes what Cardinal decides. Cedar evaluates the full closure
// either way, so narrowing a projection cannot refuse anybody anything — it can
// only stop an application being told.

func runAppGroups(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal app groups <show|mode|allow|disallow>", errUsage)
	}
	switch args[0] {
	case "show":
		return runAppGroupsShow(ctx, args[1:])
	case "mode":
		return runAppGroupsMode(ctx, args[1:])
	case "allow":
		return runAppGroupsSight(ctx, args[1:], true)
	case "disallow":
		return runAppGroupsSight(ctx, args[1:], false)
	default:
		return fmt.Errorf("%w: cardinal app groups <show|mode|allow|disallow>", errUsage)
	}
}

// runAppGroupsShow answers the question an operator actually has.
//
// "Which groups does this application see" had no answer before this existed,
// because the answer was always "all of them" and nobody had to ask.
func runAppGroupsShow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("app groups show", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal app groups show <application>", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	app, err := s.LookupEntity(ctx, directory.TypeApplication, pos[0])
	if err != nil {
		return err
	}
	projection, err := s.GroupProjectionFor(ctx, app.ID)
	if err != nil {
		return err
	}

	if projection.Mode == store.ProjectionAll {
		// Says what widening actually costs rather than only that it is on.
		//
		// Every application starts here, so a message that merely stated the
		// mode would be one nobody reads and a feature nobody turns on. The
		// number is the argument: an application told about groups it does not
		// own is learning somebody's position in the organisation to decide
		// whether they may read a wiki.
		owned, countErr := s.GroupsVisibleTo(ctx, app.ID)
		if countErr != nil {
			return countErr
		}
		total, countErr := s.GroupCount(ctx)
		if countErr != nil {
			return countErr
		}

		fmt.Printf("%s is told about every group\n\n", app.Name)
		if total > len(owned) {
			fmt.Printf("  %d group(s) exist and it owns %d, so it is told about %d that\n",
				total, len(owned), total-len(owned))
			fmt.Println("  have nothing to do with it — on every request, in the forwardAuth")
			fmt.Println("  header and in the OIDC groups claim.")
		} else {
			fmt.Println("  Every group the person belongs to reaches this application, in the")
			fmt.Println("  forwardAuth header and in the OIDC groups claim.")
		}
		fmt.Println()
		fmt.Printf("  Narrow it to the ones it owns: cardinal app groups mode %s owned\n", app.Name)
		return nil
	}

	groups, err := s.GroupsVisibleTo(ctx, app.ID)
	if err != nil {
		return err
	}

	fmt.Printf("%s is told about %d group(s)\n\n", app.Name, len(groups))
	if len(groups) == 0 {
		// Nearly always a mistake: nobody narrows a projection in order to send
		// nothing. Said here as well as in the server log, because this is where
		// somebody looks when an application stopped seeing anybody.
		fmt.Println("  Nothing — so this application is told about no groups at all,")
		fmt.Println("  whoever signs in. That is almost always a misconfiguration:")
		fmt.Printf("    cardinal app groups allow %s <group>\n", app.Name)
		fmt.Println("  or give it groups of its own with `cardinal group create -app`.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  GROUP\tHOW") //nolint:errcheck // writing to stdout; nothing actionable remains
	for _, g := range groups {
		how := "owned"
		if !g.Owned {
			how = "allowed"
		}
		fmt.Fprintf(w, "  %s\t%s\n", g.Name, how) //nolint:errcheck // as above
	}
	_ = w.Flush() //nolint:errcheck // stdout
	fmt.Println()
	fmt.Println("  A group it owns is told automatically. An allowed one was granted")
	fmt.Println("  here and can be taken back with `cardinal app groups disallow`.")
	return nil
}

func runAppGroupsMode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("app groups mode", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal app groups mode <application> <owned|all>", errUsage)
	}
	mode := pos[1]
	if mode != store.ProjectionAll && mode != store.ProjectionOwned {
		return fmt.Errorf("%w: the mode is `owned` or `all`, not %q", errUsage, mode)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	app, err := s.LookupEntity(ctx, directory.TypeApplication, pos[0])
	if err != nil {
		return err
	}
	if err := s.SetGroupProjection(ctx, app.ID, mode, nil); err != nil {
		return err
	}

	if mode == store.ProjectionAll {
		fmt.Printf("%s is now told about every group\n\n", app.Name)
		fmt.Println("  Including groups that have nothing to do with it, which is what")
		fmt.Println("  every application saw before projections existed.")
		return nil
	}
	fmt.Printf("%s is now told only about the groups it sees\n\n", app.Name)
	fmt.Printf("  Check what that comes to: cardinal app groups show %s\n", app.Name)
	fmt.Println("  Nothing about who may sign in has changed — Cardinal decides on the")
	fmt.Println("  full membership either way, and this is only what it discloses.")
	return nil
}

func runAppGroupsSight(ctx context.Context, args []string, allow bool) error {
	verb := "allow"
	if !allow {
		verb = "disallow"
	}
	fs := flag.NewFlagSet("app groups "+verb, flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal app groups %s <application> <group>", errUsage, verb)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	app, err := s.LookupEntity(ctx, directory.TypeApplication, pos[0])
	if err != nil {
		return err
	}
	group, err := s.LookupEntity(ctx, directory.TypeGroup, pos[1])
	if err != nil {
		return err
	}

	if !allow {
		if err := s.DenyGroupSight(ctx, app.ID, group.ID); err != nil {
			return err
		}
		fmt.Printf("%s is no longer told about %s\n", app.Name, group.Name)
		fmt.Println("  A group it owns is told regardless; this removes an allowance only.")
		return nil
	}

	if err := s.AllowGroupSight(ctx, app.ID, group.ID, nil); err != nil {
		return err
	}
	fmt.Printf("%s is now told about %s\n\n", app.Name, group.Name)
	fmt.Println("  Only in owned mode. In `all` mode every group already reaches it,")
	fmt.Printf("  and `cardinal app groups show %s` says which mode it is in.\n", app.Name)
	return nil
}
