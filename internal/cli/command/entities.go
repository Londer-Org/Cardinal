package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/api"
	"go.londer.be/cardinal/internal/directory"
)

// Creating an entity and taking it out of service, through the API.

// Entity dispatches `cardinal <type> <verb>`.
//
// The type is a word from the command line rather than a value, so it is
// checked here: an unknown one would otherwise become a path segment and come
// back as a 404 that reads like the entity is missing rather than the type.
func Entity(typeWord string) func(context.Context, string, cli.AuthFlow, []string) error {
	kind := directory.Type(strings.ReplaceAll(typeWord, "-", "_"))

	return func(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
		if !kind.Valid() {
			return fmt.Errorf("%w: %q is not a type this directory has", cli.ErrUsage, typeWord)
		}
		if len(args) == 0 {
			return fmt.Errorf("%w: cardinal %s <create|disable|enable> <name>",
				cli.ErrUsage, typeWord)
		}

		// Disabling is the reversible way to cut something off — that is the
		// whole reason it exists rather than a delete — so both directions live
		// together.
		switch args[0] {
		case "create":
			return createEntity(ctx, server, flow, kind, typeWord, args[1:])
		case "disable":
			return setAvailability(ctx, server, flow, kind, typeWord, args[1:], false)
		case "enable":
			return setAvailability(ctx, server, flow, kind, typeWord, args[1:], true)
		default:
			return fmt.Errorf("%w: cardinal %s <create|disable|enable> <name>",
				cli.ErrUsage, typeWord)
		}
	}
}

func createEntity(
	ctx context.Context, server string, flow cli.AuthFlow,
	kind directory.Type, typeWord string, args []string,
) error {
	fs := flag.NewFlagSet(typeWord+" create", flag.ContinueOnError)
	display := fs.String("display", "", "human-friendly display name")
	// Only meaningful for a group. Rejected rather than ignored elsewhere: a
	// flag that silently does nothing is how somebody believes they set an
	// owner. The server refuses it too, so this is the earlier of two answers
	// rather than the only one.
	owner := fs.String("app", "", "the application this group exists for (groups only)")
	invite := fs.Bool("invite", false, "issue an enrolment link in the same step (users only)")
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal %s create <name>", cli.ErrUsage, typeWord)
	}
	if *owner != "" && kind != directory.TypeGroup {
		return fmt.Errorf("%w: -app names the application a *group* belongs to, "+
			"and %s is not a group", cli.ErrUsage, typeWord)
	}
	if *invite && kind != directory.TypeUser {
		return fmt.Errorf("%w: -invite issues an enrolment link, and only a user "+
			"can sign in; %s cannot", cli.ErrUsage, typeWord)
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	if kind == directory.TypeUser {
		created, createErr := client.CreateUser(ctx, api.CreateUserRequest{
			Login:       pos[0],
			DisplayName: *display,
			Invite:      *invite,
		})
		if createErr != nil {
			return createErr
		}
		fmt.Printf("created user %s\n", created.Login)
		if created.InvitationURL == "" {
			fmt.Fprintf(os.Stderr,
				"\n  Nobody can sign in to it yet. `cardinal invite %s` prints a link,\n"+
					"  or pass -invite next time and get one in the same step.\n",
				created.Login)
			return nil
		}
		fmt.Printf("\nSend them this. It is single use and shown once:\n\n%s\n",
			created.InvitationURL)
		if created.ExpiresAt != "" {
			fmt.Printf("\n  expires  %s\n", created.ExpiresAt)
		}
		return nil
	}

	created, err := client.Create(ctx, kind, api.CreateRequest{
		Name:        pos[0],
		DisplayName: *display,
		Owner:       *owner,
	})
	if err != nil {
		return err
	}

	fmt.Printf("created %s %s\n  id %s\n", created.Type, created.Name, created.ID)
	if created.Owner != "" {
		fmt.Printf("  owned by %s, so that application is told about it\n",
			created.Owner)
	}
	if kind == directory.TypeApplication {
		// Said at creation because it is the one moment somebody is looking. An
		// application is told about every group until somebody narrows it, and a
		// feature nobody is told about is one nobody turns on.
		fmt.Println("  told about every group — narrow it with `cardinal app groups " +
			"mode " + created.Name + " owned`")
	}
	return nil
}

func setAvailability(
	ctx context.Context, server string, flow cli.AuthFlow,
	kind directory.Type, typeWord string, args []string, enable bool,
) error {
	verb := "disable"
	if enable {
		verb = "enable"
	}

	fs := flag.NewFlagSet(typeWord+" "+verb, flag.ContinueOnError)
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal %s %s <name>", cli.ErrUsage, typeWord, verb)
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	if enable {
		done, enableErr := client.Enable(ctx, kind, pos[0])
		if enableErr != nil {
			return enableErr
		}
		fmt.Printf("enabled %s %s\n", typeWord, done.Name)
		fmt.Fprintln(os.Stderr,
			"\n  Sessions and access tokens were revoked when this was disabled and\n"+
				"  have not come back. Whoever this is signs in again.")
		return nil
	}

	done, err := client.Disable(ctx, kind, pos[0])
	if err != nil {
		return err
	}

	fmt.Printf("disabled %s %s\n", typeWord, done.Name)
	fmt.Printf("  revoked %d session(s) and %d access token(s)\n",
		done.SessionsRevoked, done.TokensRevoked)
	fmt.Fprintf(os.Stderr,
		"\n  Reversible: `cardinal %s enable %s`. History and past grants are kept\n"+
			"  either way — nothing here is a delete.\n", typeWord, done.Name)
	return nil
}
