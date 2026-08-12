package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/store"
)

// runMigrate applies the embedded schema. Forward only, on purpose.
//
// This command briefly grew a `-to` that undid migrations, a reversal beside
// every migration, and a `-backup` taken first. All of it answered a question a
// simpler rule removes: migrations only add, so the previous version keeps
// working against a schema newer than itself and rolling back is deploying the
// older build. Nothing to undo, no order to remember, and no second procedure
// to be holding the wrong half of while something is already going wrong.
//
// Removal still happens, a release later, once nothing running reads the thing
// removed. A change that cannot wait says `-- breaking:` in its header and older
// versions refuse to start rather than misbehave.
//
// A separate command rather than something `serve` does on start: applying a
// schema change while other replicas still serve the old one is how rolling
// deploys break, and that should be a deliberate step.
func runMigrate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	status := fs.Bool("status", false, "list applied migrations and exit")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	// Accepted for the same reason `serve` accepts it, and because not accepting
	// it answered `cardinal migrate -config /etc/cardinal/cardinal.toml` — the
	// obvious thing to type in a container — with a usage error listing every
	// other flag. The DSN is already found at that path by convention; this just
	// lets it be said out loud, or pointed somewhere else.
	configPath := fs.String("config", "", "configuration file, for the connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}
	if *configPath != "" && *dsnFlag == "" {
		if err := os.Setenv("CARDINAL_CONFIG", *configPath); err != nil {
			return err
		}
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	if *status {
		return printStatus(ctx, s)
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

func printStatus(ctx context.Context, s *store.Store) error {
	applied, err := s.AppliedMigrations(ctx)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("no migrations applied")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MIGRATION\tDIGEST") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, m := range applied {
		fmt.Fprintf(w, "%s\t%s\n", m.Name, m.Digest[:12]) //nolint:errcheck // the header is already written, so the status cannot be changed
	}
	return w.Flush()
}
