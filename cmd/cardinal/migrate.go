package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
)

// runMigrate applies the embedded schema.
//
// A separate command rather than something `serve` does on start: applying a
// schema change while other replicas still serve the old one is how rolling
// deploys break, and that should be a deliberate step.
func runMigrate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	status := fs.Bool("status", false, "list applied migrations and exit")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	if *status {
		applied, err := s.AppliedMigrations(ctx)
		if err != nil {
			return err
		}
		if len(applied) == 0 {
			fmt.Println("no migrations applied")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "MIGRATION\tDIGEST")
		for _, m := range applied {
			fmt.Fprintf(w, "%s\t%s\n", m.Name, m.Digest[:12])
		}
		return w.Flush()
	}

	ran, err := s.Migrate(ctx)
	if err != nil {
		return err
	}
	if len(ran) == 0 {
		fmt.Println("schema is up to date")
		return nil
	}
	for _, name := range ran {
		fmt.Printf("applied %s\n", name)
	}
	fmt.Printf("%d migration(s) applied\n", len(ran))
	return nil
}
