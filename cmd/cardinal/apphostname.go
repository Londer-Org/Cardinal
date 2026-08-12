package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/directory"
)

// `cardinal app hostname …` — which addresses an application answers to.
//
// forwardAuth is handed a hostname and nothing else, so this is what lets it
// find the application, and therefore the group memberships that decide who may
// reach it. A hostname with no application is refused at the proxy, so this is
// the command that makes a protected site reachable at all.

func runAppHostname(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal app hostname <add|remove|list>", errUsage)
	}
	switch args[0] {
	case "add":
		return runAppHostnameAdd(ctx, args[1:])
	case "remove":
		return runAppHostnameRemove(ctx, args[1:])
	case "list":
		return runAppHostnameList(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal app hostname <add|remove|list>", errUsage)
	}
}

func runAppHostnameAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("app hostname add", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal app hostname add <application> <hostname>", errUsage)
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
	if addErr := s.AddApplicationHostname(ctx, app.ID, pos[1], nil); addErr != nil {
		return addErr
	}

	fmt.Printf("%s now answers for %s\n", app.Name, pos[1])

	// Registering the hostname makes the application *findable*; it does not
	// make it reachable. Saying so here is the difference between a working
	// setup and a 403 nobody can explain, since the policy set ships with
	// staff-apps empty on purpose.
	memberships, err := s.ResolveMemberships(ctx, app.ID, time.Time{})
	if err == nil && len(memberships) == 0 {
		fmt.Printf("  it is in no groups, so the shipped policy set admits nobody to it.\n")
		fmt.Printf("  `cardinal grant staff-apps %s` opens it to everyone who signs in.\n",
			app.Name)
	}
	return nil
}

func runAppHostnameRemove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("app hostname remove", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal app hostname remove <application> <hostname>", errUsage)
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
	if err := s.RemoveApplicationHostname(ctx, app.ID, pos[1], nil); err != nil {
		return err
	}

	// Immediately, unlike a certificate: forwardAuth asks on every request.
	fmt.Printf("%s no longer answers for %s — the next request there is refused\n",
		app.Name, pos[1])
	return nil
}

func runAppHostnameList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("app hostname list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := cli.Parse(fs, args)
	if err != nil {
		return errUsage
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	if len(pos) == 1 {
		app, lookupErr := s.LookupEntity(ctx, directory.TypeApplication, pos[0])
		if lookupErr != nil {
			return lookupErr
		}
		hostnames, listErr := s.ListApplicationHostnames(ctx, app.ID)
		if listErr != nil {
			return listErr
		}
		if len(hostnames) == 0 {
			fmt.Printf("%s answers for no hostnames\n", app.Name)
			return nil
		}
		for _, h := range hostnames {
			fmt.Println(h)
		}
		return nil
	}

	all, err := s.AllApplicationHostnames(ctx)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		fmt.Println("no hostnames registered — forwardAuth refuses every address")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOSTNAME\tAPPLICATION") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, h := range all {
		fmt.Fprintf(w, "%s\t%s\n", h.Hostname, h.ApplicationName) //nolint:errcheck // the header is already written, so the status cannot be changed
	}
	return w.Flush()
}
