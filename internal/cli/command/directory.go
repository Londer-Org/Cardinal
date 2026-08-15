package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/directory"
)

// Reading the directory, through the API.

// entityType turns the word somebody types into the type stored in the
// database. The CLI spells service_account with a hyphen, because a command
// line does.
func entityType(word string) directory.Type {
	return directory.Type(strings.ReplaceAll(word, "-", "_"))
}

// List reports what is in the directory.
func List(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	all := fs.Bool("all", false, "include disabled entities")
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}

	var kind directory.Type
	if len(pos) > 0 {
		kind = entityType(pos[0])
		if !kind.Valid() {
			return fmt.Errorf("%w: %q", directory.ErrInvalidType, pos[0])
		}
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	entities, err := client.Entities(ctx, kind, *all)
	if err != nil {
		return err
	}
	if len(entities) == 0 {
		fmt.Println("no entities")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tNAME\tID\tSTATUS") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, e := range entities {
		status := "active"
		if !e.Active() {
			status = "disabled " + e.DisabledAt.Format(time.DateOnly)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Type, e.Name, e.ID, status) //nolint:errcheck // the header is already written, so the status cannot be changed
	}
	return w.Flush()
}

// Show describes one entity and what it belongs to.
func Show(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal show <type> <name>", cli.ErrUsage)
	}
	kind := entityType(pos[0])
	if !kind.Valid() {
		return fmt.Errorf("%w: %q", directory.ErrInvalidType, pos[0])
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	e, err := client.Entity(ctx, kind, pos[1])
	if err != nil {
		return err
	}

	fmt.Printf("%s %s\n", e.Type, e.Name)
	fmt.Printf("  id           %s\n", e.ID)
	if e.DisplayName != "" {
		fmt.Printf("  display      %s\n", e.DisplayName)
	}
	fmt.Printf("  created      %s\n", e.CreatedAt.Format(time.RFC3339))
	if !e.Active() {
		fmt.Printf("  disabled     %s\n", e.DisabledAt.Format(time.RFC3339))
	}

	if len(e.Memberships) > 0 {
		fmt.Printf("  memberships\n")
		for _, m := range e.Memberships {
			via := fmt.Sprintf("inherited, depth %d", m.Depth)
			if m.Direct {
				via = "direct"
			}
			fmt.Printf("    %-24s %s\n", m.Group, via)
		}
	}
	return nil
}
