package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/httpapi"
	"go.londer.be/cardinal/internal/server/ssf"
	"go.londer.be/cardinal/internal/store"
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
		return fmt.Errorf("%w: cardinal ssf <stream|status|token>", errUsage)
	}
	switch args[0] {
	case "stream":
		return runSSFStream(ctx, args[1:])
	case "status":
		return runSSFStatus(ctx, args[1:])
	case "token":
		return runSSFToken(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal ssf <stream|status|token>", errUsage)
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
	endpoint := fs.String("endpoint", "", "https URL to POST events to (required for push)")
	delivery := fs.String("delivery", store.DeliveryPush,
		"push posts each event to -endpoint; poll has the receiver collect them")
	events := fs.String("events", strings.Join(ssf.AllEvents, ","),
		"comma-separated event types; the default is all of them")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal ssf stream add <application> -endpoint <url>", errUsage)
	}
	switch *delivery {
	case store.DeliveryPush:
		if *endpoint == "" {
			return fmt.Errorf("%w: -endpoint is required for push delivery", errUsage)
		}
	case store.DeliveryPoll:
		// Refused rather than ignored. Somebody who passed both wants events
		// posted somewhere, and silently keeping only one of the two answers
		// would leave them waiting for deliveries that never come.
		if *endpoint != "" {
			return fmt.Errorf("%w: a poll stream has no endpoint — the receiver "+
				"connects to Cardinal and collects what is waiting", errUsage)
		}
	default:
		return fmt.Errorf("%w: -delivery must be push or poll", errUsage)
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

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	app, err := s.LookupEntity(ctx, directory.TypeApplication, pos[0])
	if err != nil {
		return err
	}

	stream, err := s.SaveStream(ctx, app.ID, *endpoint, *delivery, wanted, nil)
	if err != nil {
		return err
	}

	if stream.DeliveryMethod == store.DeliveryPoll {
		fmt.Printf("%s collects security events by polling\n\n", stream.Name)
	} else {
		fmt.Printf("%s receives security events at %s\n\n", stream.Name, stream.Endpoint)
	}
	for _, e := range stream.Events {
		fmt.Printf("  %s\n", e)
	}
	fmt.Println()
	fmt.Println("  Tokens are signed with the OIDC signing key, so the receiver verifies")
	fmt.Println("  them against the JWKS it already fetches. Nothing new to distribute.")
	fmt.Println()
	if stream.DeliveryMethod == store.DeliveryPoll {
		fmt.Println("  The receiver needs a credential of its own to collect them:")
		fmt.Printf("    cardinal ssf token %s\n", stream.Name)
		fmt.Println()
	}
	fmt.Println("  `cardinal ssf status` shows what is queued and what is failing.")
	return nil
}

func runSSFStreamList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssf stream list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	s, err := direct.Open(ctx, *dsnFlag)
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
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal ssf stream remove <application>", errUsage)
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
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal ssf stream <pause|resume> <application>", errUsage)
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
	if err := s.SetStreamEnabled(ctx, app.ID, resume); err != nil {
		return err
	}

	if resume {
		fmt.Printf("%s is receiving again — whatever was still queued goes out now.\n",
			app.Name)
		fmt.Println("  Anything that happened while it was paused was not recorded")
		fmt.Println("  for it, so this does not catch it up.")
		return nil
	}
	// Said plainly, because the consequence is invisible and permanent. This
	// used to print "Events keep queueing, so resuming sends what was missed",
	// which is the opposite of what happens.
	fmt.Printf("%s is paused. What is already queued is kept and goes out when you\n", app.Name)
	fmt.Println("  resume, but nothing new is recorded while it is paused.")
	fmt.Println()
	fmt.Println("  So a session revoked from now until you resume is one this receiver")
	fmt.Println("  is never told about, and it will go on honouring that session until")
	fmt.Println("  the token expires on its own. Remove the stream instead if the")
	fmt.Println("  receiver is gone for good.")
	return nil
}

func runSSFStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssf status", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	s, err := direct.Open(ctx, *dsnFlag)
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

// runSSFToken issues the credential a polling receiver authenticates with.
//
// Its own command rather than `cardinal token create`, because the subject is
// an application and that command takes a login. The distinction is not
// cosmetic: this token authenticates as the receiver, which is the only
// principal that may collect the receiver's events, and issuing it to the
// administrator who happened to set the stream up would mean a person's
// credential draining an application's queue.
//
// The events scope and nothing else. A token that could also read the decision
// log because it needed to poll would be exactly the over-grant scopes exist to
// prevent.
func runSSFToken(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssf token", flag.ContinueOnError)
	name := fs.String("name", "", "what this credential is for (default: polling security events)")
	ttl := fs.Duration("ttl", 365*24*time.Hour, "how long it is valid")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal ssf token <application>", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	app, err := s.LookupEntity(ctx, directory.TypeApplication, pos[0])
	if err != nil {
		return fmt.Errorf("no such application %q", pos[0])
	}

	// Refused without a stream, and refused when that stream is pushed to.
	// A credential for collecting from a queue nothing fills, or from one whose
	// events are posted out instead, is one that authenticates perfectly and
	// returns an empty list forever — which reads as "no events happened".
	stream, err := s.StreamFor(ctx, app.ID)
	if err != nil {
		return fmt.Errorf("%s has no security event stream: add one with "+
			"`cardinal ssf stream add %s -delivery poll`", app.Name, app.Name)
	}
	if stream.DeliveryMethod != store.DeliveryPoll {
		return fmt.Errorf("%s is delivered by push, so it has nothing to poll for: "+
			"its events are posted to %s", app.Name, stream.Endpoint)
	}

	label := *name
	if label == "" {
		label = "polling security events"
	}

	token, err := s.CreateAccessToken(ctx, app.ID, label, *ttl,
		[]string{httpapi.ScopeEvents}, nil)
	if err != nil {
		return err
	}

	fmt.Printf("polling credential for %s\n\n  %s\n\n", app.Name, token.Token)
	fmt.Printf("  scopes   %s\n", strings.Join(token.Scopes, ", "))
	fmt.Printf("  expires  %s\n\n", token.ValidUntil.Format(time.RFC3339))
	fmt.Println("  Shown once and not recoverable — only its hash is stored.")
	fmt.Println()
	fmt.Println("  The receiver collects events with:")
	fmt.Println("    POST /ssf/poll   Authorization: Bearer <token>")
	fmt.Println()
	fmt.Println("  It reads only the events queued for this receiver, and can do")
	fmt.Println("  nothing else in Cardinal.")
	return nil
}
