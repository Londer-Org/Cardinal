package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/tabwriter"
	"time"

	"go.londer.be/cardinal/internal/store"
)

// runMigrate applies the embedded schema, or takes it back.
//
// A separate command rather than something `serve` does on start: applying a
// schema change while other replicas still serve the old one is how rolling
// deploys break, and that should be a deliberate step.
func runMigrate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	status := fs.Bool("status", false, "list applied migrations and exit")
	to := fs.String("to", "",
		"undo migrations until this one is the newest applied (see -status)")
	backup := fs.String("backup", "",
		"write a backup here before changing anything (requires pg_dump)")
	skipBackup := fs.Bool("skip-backup", false,
		"proceed without a backup — refused for -to unless set")
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
		return printStatus(ctx, s)
	}

	if *to != "" {
		return migrateDown(ctx, s, *to, *dsnFlag, *backup, *skipBackup)
	}

	// Forward. A backup is offered rather than required: applying a migration
	// is the ordinary path and every one of them has a reversal, so the cost of
	// getting it wrong is a downgrade rather than a restore.
	if *backup != "" {
		if dumpErr := dump(ctx, *dsnFlag, *backup); dumpErr != nil {
			return dumpErr
		}
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

// migrateDown undoes migrations, and will not do it blind.
//
// A reversal restores the *shape* of the data and not the data itself: dropping
// a column reverses to a column with nothing in it. So the interesting question
// is never "can this be undone" — it is "is what it removes still somewhere
// else", and the only version of that with a yes is a backup.
func migrateDown(ctx context.Context, s *store.Store, target, dsn, backup string, skip bool) error {
	if backup == "" && !skip {
		return errors.New(
			"refusing to undo migrations without a backup\n\n" +
				"  A reversal restores the shape of the data, not the data. Dropping a\n" +
				"  column reverses to a column with nothing in it, and nothing here can\n" +
				"  tell the difference afterwards.\n\n" +
				"  Take one with -backup <path>, or say -skip-backup if it is already\n" +
				"  somewhere safe")
	}
	if backup != "" {
		if dumpErr := dump(ctx, dsn, backup); dumpErr != nil {
			return dumpErr
		}
	}

	undone, err := s.MigrateDownTo(ctx, target)
	if err != nil {
		return err
	}
	if len(undone) == 0 {
		fmt.Printf("%s is already the newest applied migration\n", target)
		return nil
	}
	for _, name := range undone {
		fmt.Printf("reversed %s\n", name)
	}
	fmt.Printf("%d migration(s) reversed; %s is now the newest applied\n",
		len(undone), target)
	return nil
}

// dump shells out to pg_dump.
//
// Not reimplemented in Go. A backup taken by anything other than the tool whose
// restore path is documented and tested is a file somebody will discover does
// not restore at the moment they need it to — and the container image ships no
// pg_dump precisely so that this is the operator's own tooling rather than a
// second one nobody exercises.
func dump(ctx context.Context, dsn, path string) error {
	if dsn == "" {
		dsn = os.Getenv("CARDINAL_DSN")
	}
	if dsn == "" {
		return errors.New("a backup needs a connection string: pass -dsn or set CARDINAL_DSN")
	}
	if _, err := exec.LookPath("pg_dump"); err != nil {
		return fmt.Errorf(
			"pg_dump is not on PATH, so -backup cannot be honoured: %w\n\n"+
				"  The container image deliberately ships without it. Take the backup\n"+
				"  with whatever already backs this database up, then pass -skip-backup",
			err)
	}

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}

	// Bounded, because a backup that hangs holds up the migration behind it and
	// an operator watching a silent terminal cannot tell which.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	fmt.Printf("backing up to %s\n", path)
	// G204 flags the DSN and path as tainted. They are: both come from this
	// process's own flags or environment, set by whoever is already running a
	// command that can rewrite the schema. Passed as separate arguments rather
	// than through a shell, so there is nothing for a semicolon to do.
	cmd := exec.CommandContext(ctx, "pg_dump", //nolint:gosec // arguments come from this process's own flags, and no shell is involved
		"--format=custom", "--file="+path, dsn)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Removed rather than left behind. A partial dump that looks like a
		// backup is worse than no file at all, because the next person finds it
		// and believes it.
		_ = os.Remove(path) //nolint:errcheck // cleanup of a file the success path has already renamed away
		return fmt.Errorf("pg_dump failed, and the partial file was removed: %w\n%s",
			err, output)
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("pg_dump reported success but wrote nothing to %s: %w", path, err)
	}
	fmt.Printf("  %d bytes\n", info.Size())
	return nil
}
