package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
)

// runDecisions prints the decision log.
//
// The decision explorer was in the console long before it was here, which is
// the wrong way round for the question it answers. "Why was
// this denied" is asked while something is broken — during an incident, from a
// terminal, over SSH, quite possibly because the console itself is what cannot
// be reached — and it is the question neither FreeIPA nor Keycloak can answer
// at all.
func runDecisions(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("decisions", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	deniedOnly := fs.Bool("denied", false, "only decisions that refused something")
	limit := fs.Int("limit", 20, "how many to show, newest first")

	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) > 1 {
		return fmt.Errorf("%w: cardinal decisions [<principal>] [-denied] [-limit n]", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	// A named principal filters the log; naming none shows everything.
	var principal *uuid.UUID
	if len(pos) == 1 {
		member, resolveErr := resolveMember(ctx, s, pos[0])
		if resolveErr != nil {
			return resolveErr
		}
		principal = &member.ID
	}

	decisions, err := s.RecentDecisions(ctx, principal, *deniedOnly, *limit)
	if err != nil {
		return err
	}
	if len(decisions) == 0 {
		fmt.Println("no decisions recorded yet")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "POINT\tACTION\tRESOURCE\tRESULT\tPOLICY") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, d := range decisions {
		result := "allowed"
		if !d.Allowed {
			result = "DENIED"
		}

		// The deciding policy, which is the whole point of the log. Empty means
		// nothing matched and the default-deny applied — worth saying in words,
		// because a blank column reads as missing data rather than as the
		// answer.
		reason := strings.Join(d.Reasons, ",")
		if reason == "" {
			reason = "(none matched: default-deny)"
		}
		if len(d.Errors) > 0 {
			reason += " !" + strings.Join(d.Errors, ",")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck // the header is already written, so the status cannot be changed
			d.DecisionPoint, d.Action, d.Resource, result, reason)
	}
	return w.Flush()
}
