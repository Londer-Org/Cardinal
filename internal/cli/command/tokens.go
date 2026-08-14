package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/api"
	"go.londer.be/cardinal/internal/cli/auth"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/httpapi"
)

// Access tokens, through the API.

// Token dispatches `cardinal token`.
func Token(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal token <create|list|revoke>", cli.ErrUsage)
	}

	switch args[0] {
	case "create":
		return tokenCreate(ctx, server, flow, args[1:])
	case "list":
		return tokenList(ctx, server, flow, args[1:])
	case "revoke":
		return tokenRevoke(ctx, server, flow, args[1:])
	default:
		return fmt.Errorf("%w: cardinal token <create|list|revoke>", cli.ErrUsage)
	}
}

// notFound reports whether an error is the API saying it has no such thing.
func notFound(err error) bool {
	var refused *auth.Refused
	return errors.As(err, &refused) && refused.Status == http.StatusNotFound
}

// subjectKind finds which kind of account a name belongs to.
//
// Tokens hang off a type-specific path and the command line carries a bare
// name, so one of the two has to be tried. A person first, because that is
// most names; a service account second, because that is most tokens.
func subjectKind(ctx context.Context, client *api.Client, name string) (directory.Type, error) {
	if _, _, err := client.UserPOSIX(ctx, name); err == nil {
		return directory.TypeUser, nil
	} else if !notFound(err) {
		return "", err
	}

	// No read endpoint for a service account, so its token listing is the
	// probe: it answers 404 for a name that is not one, and an empty list for
	// one that exists and holds nothing.
	if _, err := client.Tokens(ctx, directory.TypeServiceAccount, name); err == nil {
		return directory.TypeServiceAccount, nil
	} else if !notFound(err) {
		return "", err
	}

	return "", fmt.Errorf("no user or service account named %q", name)
}

func tokenCreate(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	name := fs.String("name", "", "what the token is for (required)")
	// Bounded by default, like a membership grant. A credential nobody chose an
	// end date for is one nobody will remember to withdraw.
	ttl := fs.Duration("for", 90*24*time.Hour, "how long it stays valid")
	scopes := fs.String("scope", "",
		"comma-separated, and required: "+strings.Join(httpapi.AllScopes, ", "))

	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal token create <service-account> -name <text>",
			cli.ErrUsage)
	}
	if *name == "" {
		return fmt.Errorf("%w: -name is required", cli.ErrUsage)
	}

	// Required, deliberately. What a token used to carry — everything its owner
	// can do without a hardware key — is a grant nobody would write down on
	// purpose, and a default is how it would go on being carried.
	var wanted []string
	for _, scope := range strings.Split(*scopes, ",") {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if !httpapi.ValidScope(scope) {
			return fmt.Errorf("%w: no such scope %q; Cardinal knows %s",
				cli.ErrUsage, scope, strings.Join(httpapi.AllScopes, ", "))
		}
		wanted = append(wanted, scope)
	}
	if len(wanted) == 0 {
		return fmt.Errorf("%w: -scope is required, one or more of %s. A token "+
			"with no scope can authenticate and nothing else",
			cli.ErrUsage, strings.Join(httpapi.AllScopes, ", "))
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	issued, err := client.IssueToken(ctx, directory.TypeServiceAccount, pos[0],
		api.IssueTokenRequest{
			Name:   *name,
			Days:   int(ttl.Hours() / 24),
			Scopes: wanted,
		})
	if err != nil {
		if !notFound(err) {
			return err
		}
		// Not a service account. Whether it is a person decides which of two
		// different things to say, and only this path pays for finding out.
		if _, _, userErr := client.UserPOSIX(ctx, pos[0]); userErr == nil {
			return fmt.Errorf(
				"%s is a person, and this issues tokens for service accounts.\n"+
					"  A token issued for somebody by somebody else acts as them, with\n"+
					"  their name on the audit trail — so they make their own, from\n"+
					"  Access → Tokens in the console", pos[0])
		}
		return fmt.Errorf("no service account named %q", pos[0])
	}

	fmt.Printf("access token for %s\n\n  %s\n\n", issued.Subject, issued.Token)
	fmt.Printf("  name     %s\n", issued.Name)
	fmt.Printf("  scopes   %s\n", strings.Join(issued.Scopes, ", "))
	fmt.Printf("  expires  %s\n\n", issued.ExpiresAt.Format(time.RFC3339))
	fmt.Println("  Shown once and not recoverable — only its hash is stored.")
	fmt.Println("  Send it as `Authorization: Bearer <token>`.")
	fmt.Println()
	fmt.Println("  It authenticates as this account but is never device-bound, so")
	fmt.Println("  policy refuses it administrative actions and SSH certificates.")
	fmt.Println("  Revoke with `cardinal token revoke " + issued.Subject + " <id>`.")
	return nil
}

func tokenList(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal token list <login>", cli.ErrUsage)
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	kind, err := subjectKind(ctx, client, pos[0])
	if err != nil {
		return err
	}
	tokens, err := client.Tokens(ctx, kind, pos[0])
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		fmt.Printf("%s has no access tokens\n", pos[0])
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tPREFIX\tSCOPES\tEXPIRES\tLAST USED") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, t := range tokens {
		state := t.ExpiresAt.Format("2006-01-02")
		if t.Expired {
			state += " (ended)"
		}
		lastUsed := "never"
		if t.LastUsedAt != nil {
			lastUsed = t.LastUsedAt.Format("2006-01-02 15:04")
		}
		// Shown because "what is this token allowed to do" is the question
		// somebody has when deciding whether the one in a pipeline is the one
		// they meant to create.
		scopes := strings.Join(t.Scopes, ",")
		if scopes == "" {
			scopes = "none"
		}
		fmt.Fprintf(w, "%s\t%s\t%s…\t%s\t%s\t%s\n", //nolint:errcheck // the header is already written, so the status cannot be changed
			t.ID, t.Name, t.Prefix, scopes, state, lastUsed)
	}
	return w.Flush()
}

func tokenRevoke(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	pos, err := parse(fs, args)
	if err != nil {
		return cli.ErrUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal token revoke <login> <token-id>", cli.ErrUsage)
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	kind, err := subjectKind(ctx, client, pos[0])
	if err != nil {
		return err
	}
	if err := client.RevokeToken(ctx, kind, pos[0], pos[1]); err != nil {
		if notFound(err) {
			return fmt.Errorf("no live token %s for %s — see `cardinal token list %s`",
				pos[1], pos[0], pos[0])
		}
		return err
	}

	fmt.Printf("revoked %s\n", pos[1])
	fmt.Println("  The row survives, with its window closed — an audit that cannot")
	fmt.Println("  see a credential ever existed is worse than one that can.")
	return nil
}
