package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/ssf"
)

// `cardinal ssf …` — telling applications when access changes.
//
// Streams are configured here rather than by the receiver over the API, and the
// SSF configuration document says so. Stream management is a large piece of
// protocol whose absence a receiver handles by being told its endpoint once;
// what a receiver genuinely cannot work without is the token format and the
// delivery, which are implemented.

func runSSF(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal ssf <stream|status>", errUsage)
	}
	switch args[0] {
	case "stream":
		return runSSFStream(ctx, args[1:])
	case "status":
		return runSSFStatus(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal ssf <stream|status>", errUsage)
	}
}

func runSSFStream(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal ssf stream <add|list|remove|pause|resume>", errUsage)
	}
	switch args[0] {
	case "add":
		return runSSFStreamAdd(ctx, args[1:])
	case "list":
		return runSSFStreamList(ctx, args[1:])
	case "remove":
		return runSSFStreamRemove(ctx, args[1:])
	case "pause", "resume":
		return runSSFStreamState(ctx, args[0] == "resume", args[1:])
	default:
		return fmt.Errorf("%w: cardinal ssf stream <add|list|remove|pause|resume>", errUsage)
	}
}

func runSSFStreamAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssf stream add", flag.ContinueOnError)
	endpoint := fs.String("endpoint", "", "https URL to POST events to (required)")
	events := fs.String("events", strings.Join(ssf.AllEvents, ","),
		"comma-separated event types; the default is all of them")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal ssf stream add <application> -endpoint <url>", errUsage)
	}
	if *endpoint == "" {
		return fmt.Errorf("%w: -endpoint is required", errUsage)
	}

	var wanted []string
	for _, e := range strings.Split(*events, ",") {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		if !ssf.Valid(e) {
			return fmt.Errorf("%w: %s is not an event Cardinal transmits; it knows:\n  %s",
				errUsage, e, strings.Join(ssf.AllEvents, "\n  "))
		}
		wanted = append(wanted, e)
	}
	if len(wanted) == 0 {
		return fmt.Errorf("%w: a stream with no events receives nothing", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	app, err := s.LookupEntity(ctx, directory.TypeApplication, pos[0])
	if err != nil {
		return err
	}

	stream, err := s.SaveStream(ctx, app.ID, *endpoint, wanted, nil)
	if err != nil {
		return err
	}

	fmt.Printf("%s receives security events at %s\n\n", stream.Name, stream.Endpoint)
	for _, e := range stream.Events {
		fmt.Printf("  %s\n", e)
	}
	fmt.Println()
	fmt.Println("  Tokens are signed with the OIDC signing key, so the receiver verifies")
	fmt.Println("  them against the JWKS it already fetches. Nothing new to distribute.")
	fmt.Println()
	fmt.Println("  `cardinal ssf status` shows what is queued and what is failing.")
	return nil
}

func runSSFStreamList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssf stream list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	streams, err := s.ListStreams(ctx)
	if err != nil {
		return err
	}
	if len(streams) == 0 {
		fmt.Println("no receivers configured — a revocation here reaches nothing")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "APPLICATION\tSTATE\tENDPOINT\tEVENTS") //nolint:errcheck // the header is already written
	for _, st := range streams {
		state := "enabled"
		if !st.Enabled {
			state = "paused"
		}
		short := make([]string, 0, len(st.Events))
		for _, e := range st.Events {
			short = append(short, e[strings.LastIndex(e, "/")+1:])
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", //nolint:errcheck // as above
			st.Name, state, st.Endpoint, strings.Join(short, ","))
	}
	return w.Flush()
}

func runSSFStreamRemove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssf stream remove", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal ssf stream remove <application>", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	app, err := s.LookupEntity(ctx, directory.TypeApplication, pos[0])
	if err != nil {
		return err
	}
	if err := s.DeleteStream(ctx, app.ID); err != nil {
		return err
	}
	fmt.Printf("%s no longer receives security events\n", app.Name)
	fmt.Println("  Anything still queued for it was discarded: it was addressed to a")
	fmt.Println("  receiver that no longer exists.")
	return nil
}

func runSSFStreamState(ctx context.Context, resume bool, args []string) error {
	fs := flag.NewFlagSet("ssf stream state", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal ssf stream <pause|resume> <application>", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	app, err := s.LookupEntity(ctx, directory.TypeApplication, pos[0])
	if err != nil {
		return err
	}
	if err := s.SetStreamEnabled(ctx, app.ID, resume); err != nil {
		return err
	}

	if resume {
		fmt.Printf("%s is receiving again — anything queued while it was paused goes now\n",
			app.Name)
		return nil
	}
	fmt.Printf("%s is paused. Events keep queueing, so resuming sends what was missed\n",
		app.Name)
	return nil
}

func runSSFStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssf status", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	streams, err := s.ListStreams(ctx)
	if err != nil {
		return err
	}
	pending, failing, err := s.PendingEvents(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("%d receiver(s), %d event(s) queued", len(streams), pending)
	if failing > 0 {
		// Named separately because the two mean different things: queued is
		// normal for a second, and failing means somebody is not being told.
		fmt.Printf(", %d failing after more than three attempts", failing)
	}
	fmt.Println()

	if failing > 0 {
		fmt.Println()
		fmt.Println("  A failing event is an application that still believes a revoked")
		fmt.Println("  session is good. `cardinal ssf stream list` shows the endpoints.")
	}
	return nil
}
