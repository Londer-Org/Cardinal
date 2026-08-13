// Package command holds the commands that reach Cardinal's API.
//
// Nothing here may import internal/store, and a test in internal/lint enforces
// it. One store.Open in a command restores everything ADR 0033 removes — no
// policy on the path, and no truthful actor in the journal — and it would look
// like an ordinary import in an ordinary file.
package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/api"
	"go.londer.be/cardinal/internal/cli/render"
)

// Grant adds somebody to a group.
func Grant(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	for_ := fs.Duration("for", 0, "how long the membership lasts, e.g. 72h")
	until := fs.String("until", "", "when it ends, RFC3339")
	reason := fs.String("reason", "", "why, preserved even after revocation")
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal grant <group> <member>", cli.ErrUsage)
	}

	req := api.GrantRequest{Member: pos[1], Reason: *reason}
	switch {
	case *for_ > 0 && *until != "":
		return fmt.Errorf("%w: -for and -until say the same thing two ways", cli.ErrUsage)
	case *for_ > 0:
		end := time.Now().Add(*for_)
		req.Until = &end
	case *until != "":
		end, parseErr := time.Parse(time.RFC3339, *until)
		if parseErr != nil {
			return fmt.Errorf("-until must be an RFC3339 instant: %w", parseErr)
		}
		req.Until = &end
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	if err := client.Grant(ctx, pos[0], req); err != nil {
		return err
	}

	fmt.Printf("granted %s membership of %s\n", pos[1], pos[0])
	if req.Until == nil {
		fmt.Printf("  note    consider -for or -until; unbounded grants are the ones that get forgotten\n")
	} else {
		fmt.Printf("  until   %s\n", req.Until.Format(time.RFC3339))
	}
	return nil
}

// Revoke ends a membership, keeping its history.
func Revoke(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	at := fs.String("at", "", "revocation instant, RFC3339 (default: now)")
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal revoke <group> <member>", cli.ErrUsage)
	}
	when, err := instant(*at)
	if err != nil {
		return err
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	if err := client.Revoke(ctx, pos[0], pos[1], when); err != nil {
		return err
	}

	fmt.Printf("revoked %s from %s, at %s\n", pos[1], pos[0], describeInstant(when))
	fmt.Printf("  the grant keeps its history, including the reason it was made for\n")
	return nil
}

// Members lists who is in a group, now or at an instant.
func Members(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("members", flag.ContinueOnError)
	at := fs.String("at", "", "instant to query, RFC3339 (default: now)")
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal members <group>", cli.ErrUsage)
	}
	when, err := instant(*at)
	if err != nil {
		return err
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	grants, err := client.Members(ctx, pos[0], when)
	if err != nil {
		return err
	}

	fmt.Printf("%s has, at %s\n", pos[0], describeInstant(when))
	if len(grants) == 0 {
		fmt.Println("  nobody")
		return nil
	}
	rows := make([][]string, 0, len(grants))
	for _, g := range grants {
		rows = append(rows, []string{"  " + g.Member, period(g), g.Reason})
	}
	render.Table(os.Stdout, nil, rows)
	return nil
}

// Memberships lists the groups somebody is directly in.
func Memberships(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("memberships", flag.ContinueOnError)
	at := fs.String("at", "", "instant to query, RFC3339 (default: now)")
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal memberships <user>", cli.ErrUsage)
	}
	when, err := instant(*at)
	if err != nil {
		return err
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	grants, err := client.Memberships(ctx, pos[0], when)
	if err != nil {
		return err
	}

	fmt.Printf("%s belongs to, at %s\n", pos[0], describeInstant(when))
	if len(grants) == 0 {
		fmt.Println("  nothing")
		return nil
	}
	rows := make([][]string, 0, len(grants))
	for _, g := range grants {
		rows = append(rows, []string{"  " + g.Group, period(g), g.Reason})
	}
	render.Table(os.Stdout, nil, rows)
	return nil
}

// History prints every grant ever made of one membership.
func History(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	at := fs.String("at", "", "answer for one instant instead: was this member in this group then")
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal history <group> <member>", cli.ErrUsage)
	}
	when, err := instant(*at)
	if err != nil {
		return err
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	out, err := client.GrantHistory(ctx, pos[0], pos[1], when)
	if err != nil {
		return err
	}

	if out.MemberAt != nil {
		answer := "no"
		if *out.MemberAt {
			answer = "yes"
		}
		fmt.Printf("%s in %s at %s: %s\n\n", out.Member, out.Group, out.At, answer)
	}

	fmt.Printf("every grant of %s to %s\n", out.Group, out.Member)
	if len(out.Grants) == 0 {
		fmt.Println("  none, ever")
		return nil
	}
	rows := make([][]string, 0, len(out.Grants))
	for _, g := range out.Grants {
		state := "expired"
		if g.Current {
			state = "current"
		}
		rows = append(rows, []string{"  " + state, period(g), g.Reason})
	}
	render.Table(os.Stdout, nil, rows)
	return nil
}
