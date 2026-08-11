package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/config"
	"go.londer.be/cardinal/internal/store"
)

func runApp(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal app <register|list|hostname|groups>", errUsage)
	}
	switch args[0] {
	case "register":
		return runAppRegister(ctx, args[1:])
	case "list":
		return runAppList(ctx, args[1:])
	case "hostname":
		return runAppHostname(ctx, args[1:])
	case "groups":
		return runAppGroups(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal app <register|list|hostname|groups>", errUsage)
	}
}

func runAppRegister(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("app register", flag.ContinueOnError)
	display := fs.String("display", "", "human-friendly name")
	redirect := fs.String("redirect", "", "comma-separated redirect URIs (required)")
	confidential := fs.Bool("confidential", false,
		"issue a client secret; only for servers that can keep one")
	devMode := fs.Bool("dev-mode", false,
		"permit plain http redirect URIs — never in production")
	consent := fs.Bool("consent", false,
		"ask the user before releasing claims; for third-party applications. "+
			"A prompt on a first-party app is one more thing people dismiss unread")
	scopes := fs.String("scopes", "openid,profile,email,groups", "comma-separated scopes")
	configPath := fs.String("config", "", "configuration file, for the recovery-domain check")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal app register <name> -redirect <uri>[,<uri>]", errUsage)
	}
	if *redirect == "" {
		return fmt.Errorf("%w: -redirect is required", errUsage)
	}

	method := store.AuthNone
	if *confidential {
		method = store.AuthClientSecretBasic
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	// The recovery-domain check needs configuration. Without it registration
	// still works — it is only unavailable, not silently skipped, and the
	// difference is stated below.
	var check func(string) error
	cfg, cfgErr := loadConfigForCheck(*configPath)
	if cfgErr == nil {
		check = cfg.CheckRelyingPartyDomain
	}

	registered, err := s.RegisterOIDCClient(ctx, store.RegisterClientInput{
		Name:           pos[0],
		DisplayName:    *display,
		AuthMethod:     method,
		RedirectURIs:   splitList(*redirect),
		Scopes:         splitList(*scopes),
		DevMode:        *devMode,
		RequireConsent: *consent,
	}, check, nil)
	if err != nil {
		return err
	}

	fmt.Printf("registered application %s\n", registered.Client.Name)
	fmt.Printf("  client_id     %s\n", registered.Client.ClientID)
	if registered.Secret != "" {
		fmt.Printf("  client_secret %s\n", registered.Secret)
		fmt.Printf("\n  The secret is shown once and is not recoverable — only its\n")
		fmt.Printf("  hash is stored. Put it wherever this deployment keeps secrets.\n")
	} else {
		fmt.Printf("  no secret — a public client, protected by PKCE\n")
	}
	if cfgErr != nil {
		fmt.Printf("\n  Note: no configuration was readable, so the recovery-domain\n")
		fmt.Printf("  check did not run. Pass -config to enable it.\n")
	}
	return nil
}

func runAppList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("app list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	clients, err := s.ListOIDCClients(ctx)
	if err != nil {
		return err
	}
	if len(clients) == 0 {
		fmt.Println("no applications registered")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tCLIENT ID\tAUTH\tPKCE\tCONSENT\tDEV\tREDIRECT URIS") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, c := range clients {
		dev := ""
		if c.DevMode {
			// Visible on purpose: plain-http redirects in a production listing
			// should stand out.
			dev = "yes"
		}
		pkce := "required"
		if !c.RequirePKCE {
			pkce = "NOT REQUIRED"
		}
		consent := "no"
		if c.RequireConsent {
			consent = "yes"
		}
		fmt.Fprintf(w, "%s\t%s…\t%s\t%s\t%s\t%s\t%s\n", //nolint:errcheck // the header is already written, so the status cannot be changed
			c.Name, c.ClientID[:12], c.AuthMethod, pkce, consent, dev,
			strings.Join(c.RedirectURIs, " "))
	}
	return w.Flush()
}

// loadConfigForCheck reads configuration for the recovery-domain check.
func loadConfigForCheck(path string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	for _, candidate := range configSearchPaths {
		if cfg, err := config.Load(candidate); err == nil {
			return cfg, nil
		}
	}
	return nil, errors.New("no readable configuration")
}

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
