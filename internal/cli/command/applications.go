package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/api"
)

// Applications, through the API.

// App dispatches `cardinal app`.
func App(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal app <register|list|hostname|groups>", cli.ErrUsage)
	}

	switch args[0] {
	case "register":
		return appRegister(ctx, server, flow, args[1:])
	case "list":
		return appList(ctx, server, flow, args[1:])
	case "hostname":
		return appHostname(ctx, server, flow, args[1:])
	case "groups":
		return appGroups(ctx, server, flow, args[1:])
	default:
		return fmt.Errorf("%w: cardinal app <register|list|hostname|groups>", cli.ErrUsage)
	}
}

func appRegister(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("app register", flag.ContinueOnError)
	display := fs.String("display", "", "human-friendly name")
	redirect := fs.String("redirect", "", "comma-separated redirect URIs")
	confidential := fs.Bool("confidential", false,
		"issue a client secret; only for servers that can keep one")
	devMode := fs.Bool("dev-mode", false,
		"permit plain http redirect URIs — never in production")
	consent := fs.Bool("consent", false,
		"ask the user before releasing claims; for third-party applications. "+
			"A prompt on a first-party app is one more thing people dismiss unread")
	scopes := fs.String("scopes", "openid,profile,email,groups", "comma-separated scopes")

	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal app register <name> [-redirect <uri>[,<uri>]]",
			cli.ErrUsage)
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	// No redirect URIs is a whole category rather than a missing flag: an
	// application behind the proxy speaks no OIDC and has nothing to redirect
	// to. It was required here and optional in the console, so the same request
	// was refused from a terminal and accepted from a browser.
	registered, err := client.Register(ctx, api.RegisterRequest{
		Name:           pos[0],
		DisplayName:    *display,
		RedirectURIs:   splitList(*redirect),
		Scopes:         splitList(*scopes),
		Confidential:   *confidential,
		RequireConsent: *consent,
		DevMode:        *devMode,
	})
	if err != nil {
		return err
	}

	fmt.Printf("registered application %s\n", pos[0])
	if registered.ClientID == "" {
		fmt.Println("  no OIDC client — it has no redirect URIs, so it is an entity to")
		fmt.Println("  write policy about and a name a hostname can belong to")
		return nil
	}

	fmt.Printf("  client_id     %s\n", registered.ClientID)
	if registered.Secret == "" {
		fmt.Printf("  no secret — a public client, protected by PKCE\n")
		return nil
	}
	fmt.Printf("  client_secret %s\n", registered.Secret)
	fmt.Printf("\n  The secret is shown once and is not recoverable — only its\n")
	fmt.Printf("  hash is stored. Put it wherever this deployment keeps secrets.\n")
	return nil
}

func appList(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("app list", flag.ContinueOnError)
	if _, err := parse(fs, args); err != nil {
		return cli.ErrUsage
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	apps, err := client.Applications(ctx)
	if err != nil {
		return err
	}
	if len(apps) == 0 {
		fmt.Println("no applications registered")
		return nil
	}

	// Every application, not only the ones with an OIDC client. The listing
	// this replaced read the relying-party table, so an application reached
	// only through the proxy was registered, worked, and did not appear.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tCLIENT ID\tAUTH\tPKCE\tCONSENT\tDEV\tHOSTNAMES / REDIRECT URIS") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, a := range apps {
		name := a.Name
		if a.Disabled {
			name += " (disabled)"
		}
		if a.OIDC == nil {
			fmt.Fprintf(w, "%s\t—\t—\t—\t—\t—\t%s\n", //nolint:errcheck // as above
				name, strings.Join(a.Hostnames, " "))
			continue
		}
		dev := ""
		if a.OIDC.DevMode {
			// Visible on purpose: plain-http redirects in a production listing
			// should stand out.
			dev = "yes"
		}
		pkce := "required"
		if !a.OIDC.RequirePKCE {
			pkce = "NOT REQUIRED"
		}
		consent := "no"
		if a.OIDC.RequireConsent {
			consent = "yes"
		}
		fmt.Fprintf(w, "%s\t%s…\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck // as above
			name, truncate(a.OIDC.ClientID, 12), a.OIDC.AuthMethod, pkce, consent, dev,
			strings.Join(append(a.Hostnames, a.OIDC.RedirectURIs...), " "))
	}
	return w.Flush()
}

func appHostname(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal app hostname <add|remove|list>", cli.ErrUsage)
	}
	verb, rest := args[0], args[1:]

	fs := flag.NewFlagSet("app hostname "+verb, flag.ContinueOnError)
	pos, err := parse(fs, rest)
	if err != nil {
		return cli.ErrUsage
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	switch verb {
	case "add":
		if len(pos) != 2 {
			return fmt.Errorf("%w: cardinal app hostname add <application> <hostname>",
				cli.ErrUsage)
		}
		added, addErr := client.AddHostname(ctx, pos[0], pos[1])
		if addErr != nil {
			return addErr
		}
		fmt.Printf("%s now answers for %s\n", pos[0], pos[1])
		if !added.InAnyGroup {
			// Registering the hostname makes the application findable; it does
			// not make it reachable. The shipped policy set has staff-apps empty
			// on purpose, so this is the difference between a working setup and
			// a 403 nobody can explain.
			fmt.Printf("  it is in no groups, so the shipped policy set admits nobody to it.\n")
			fmt.Printf("  `cardinal grant staff-apps %s` opens it to everyone who signs in.\n",
				pos[0])
		}
		return nil

	case "remove":
		if len(pos) != 2 {
			return fmt.Errorf("%w: cardinal app hostname remove <application> <hostname>",
				cli.ErrUsage)
		}
		if err := client.RemoveHostname(ctx, pos[0], pos[1]); err != nil {
			return err
		}
		// Immediately, unlike a certificate: forwardAuth asks on every request.
		fmt.Printf("%s no longer answers for %s — the next request there is refused\n",
			pos[0], pos[1])
		return nil

	case "list":
		if len(pos) > 1 {
			return fmt.Errorf("%w: cardinal app hostname list [<application>]", cli.ErrUsage)
		}
		apps, listErr := client.Applications(ctx)
		if listErr != nil {
			return listErr
		}

		// No application named lists the estate, which answers a different
		// question and is the one asked during an incident: which addresses
		// does forwardAuth know about at all.
		if len(pos) == 0 {
			return listEveryHostname(apps)
		}

		for _, a := range apps {
			if a.Name != pos[0] {
				continue
			}
			if len(a.Hostnames) == 0 {
				fmt.Printf("%s answers for no hostnames\n", a.Name)
				fmt.Println("  Which is ordinary for an application reached over OIDC rather")
				fmt.Println("  than through the proxy.")
				return nil
			}
			for _, h := range a.Hostnames {
				fmt.Println(h)
			}
			return nil
		}
		return fmt.Errorf("no such application: %s", pos[0])

	default:
		return fmt.Errorf("%w: cardinal app hostname <add|remove|list>", cli.ErrUsage)
	}
}

func appGroups(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal app groups <show|mode|allow|disallow>", cli.ErrUsage)
	}
	verb, rest := args[0], args[1:]

	fs := flag.NewFlagSet("app groups "+verb, flag.ContinueOnError)
	pos, err := parse(fs, rest)
	if err != nil {
		return cli.ErrUsage
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	switch verb {
	case "show":
		if len(pos) != 1 {
			return fmt.Errorf("%w: cardinal app groups show <application>", cli.ErrUsage)
		}
		return showProjection(ctx, client, pos[0])

	case "mode":
		if len(pos) != 2 {
			return fmt.Errorf("%w: cardinal app groups mode <application> <owned|all>",
				cli.ErrUsage)
		}
		if pos[1] != "owned" && pos[1] != "all" {
			return fmt.Errorf("%w: the mode is `owned` or `all`, not %q", cli.ErrUsage, pos[1])
		}
		if err := client.SetProjectionMode(ctx, pos[0], pos[1]); err != nil {
			return err
		}
		if pos[1] == "all" {
			fmt.Printf("%s is now told about every group\n\n", pos[0])
			fmt.Println("  Including groups that have nothing to do with it, which is what")
			fmt.Println("  every application saw before projections existed.")
			return nil
		}
		fmt.Printf("%s is now told only about the groups it sees\n\n", pos[0])
		fmt.Printf("  Check what that comes to: cardinal app groups show %s\n", pos[0])
		fmt.Println("  Nothing about who may sign in has changed — Cardinal decides on the")
		fmt.Println("  full membership either way, and this is only what it discloses.")
		return nil

	case "allow", "disallow":
		if len(pos) != 2 {
			return fmt.Errorf("%w: cardinal app groups %s <application> <group>",
				cli.ErrUsage, verb)
		}
		if verb == "disallow" {
			if err := client.RevokeSight(ctx, pos[0], pos[1]); err != nil {
				return err
			}
			fmt.Printf("%s is no longer told about %s\n", pos[0], pos[1])
			fmt.Println("  A group it owns is told regardless; this removes an allowance only.")
			return nil
		}
		if err := client.GrantSight(ctx, pos[0], pos[1]); err != nil {
			return err
		}
		fmt.Printf("%s is now told about %s\n\n", pos[0], pos[1])
		fmt.Println("  Only in owned mode. In `all` mode every group already reaches it,")
		fmt.Printf("  and `cardinal app groups show %s` says which mode it is in.\n", pos[0])
		return nil

	default:
		return fmt.Errorf("%w: cardinal app groups <show|mode|allow|disallow>", cli.ErrUsage)
	}
}

func showProjection(ctx context.Context, client *api.Client, app string) error {
	projection, err := client.Projection(ctx, app)
	if err != nil {
		return err
	}

	if projection.Mode == "all" {
		// Says what widening actually costs rather than only that it is on.
		//
		// Every application starts here, so a message that merely stated the
		// mode would be one nobody reads and a feature nobody turns on. The
		// number is the argument: an application told about groups it does not
		// own is learning somebody's position in the organisation to decide
		// whether they may read a wiki.
		fmt.Printf("%s is told about every group\n\n", app)
		if projection.TotalGroups > len(projection.Groups) {
			fmt.Printf("  %d group(s) exist and it owns %d, so it is told about %d that\n",
				projection.TotalGroups, len(projection.Groups),
				projection.TotalGroups-len(projection.Groups))
			fmt.Println("  have nothing to do with it — on every request, in the forwardAuth")
			fmt.Println("  header and in the OIDC groups claim.")
		} else {
			fmt.Println("  Every group the person belongs to reaches this application, in the")
			fmt.Println("  forwardAuth header and in the OIDC groups claim.")
		}
		fmt.Println()
		fmt.Printf("  Narrow it to the ones it owns: cardinal app groups mode %s owned\n", app)
		return nil
	}

	fmt.Printf("%s is told about %d group(s)\n\n", app, len(projection.Groups))
	if len(projection.Groups) == 0 {
		// Nearly always a mistake: nobody narrows a projection in order to send
		// nothing. Said here as well as in the server log, because this is where
		// somebody looks when an application stopped seeing anybody.
		fmt.Println("  Nothing — so this application is told about no groups at all,")
		fmt.Println("  whoever signs in. That is almost always a misconfiguration:")
		fmt.Printf("    cardinal app groups allow %s <group>\n", app)
		fmt.Println("  or give it groups of its own with `cardinal group create -app`.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  GROUP\tHOW") //nolint:errcheck // writing to stdout; nothing actionable remains
	for _, g := range projection.Groups {
		how := "owned"
		if !g.Owned {
			how = "allowed"
		}
		fmt.Fprintf(w, "  %s\t%s\n", g.Name, how) //nolint:errcheck // as above
	}
	_ = w.Flush() //nolint:errcheck // stdout
	fmt.Println()
	fmt.Println("  A group it owns is told automatically. An allowed one was granted")
	fmt.Println("  here and can be taken back with `cardinal app groups disallow`.")
	return nil
}

// listEveryHostname prints the whole estate, hostname first: forwardAuth is
// handed an address and has to find an application, so that is the order the
// question arrives in.
func listEveryHostname(apps []api.Application) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	found := false
	for _, a := range apps {
		for _, h := range a.Hostnames {
			if !found {
				fmt.Fprintln(w, "HOSTNAME\tAPPLICATION") //nolint:errcheck // the header is already written, so the status cannot be changed
				found = true
			}
			fmt.Fprintf(w, "%s\t%s\n", h, a.Name) //nolint:errcheck // as above
		}
	}
	if !found {
		fmt.Println("no hostnames registered — forwardAuth refuses every address")
		return nil
	}
	return w.Flush()
}

// splitList turns a comma-separated flag into a slice, ignoring empties so a
// trailing comma is not a value.
func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// truncate shortens a client id for a listing without panicking on a short one.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
