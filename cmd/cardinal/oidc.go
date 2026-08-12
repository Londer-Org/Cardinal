package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/config"
	"go.londer.be/cardinal/internal/store"
)

func runOIDC(ctx context.Context, args []string) error {
	usage := fmt.Errorf("%w: cardinal oidc key <list|rotate>", errUsage)
	if len(args) < 2 || args[0] != "key" {
		return usage
	}

	switch args[1] {
	case "list":
		return runOIDCKeyList(ctx, args[2:])
	case "rotate":
		return runOIDCKeyRotate(ctx, args[2:])
	default:
		return usage
	}
}

// oidcSealKey resolves the key that encrypts the signing key at rest.
//
// From configuration rather than a flag, for the reason the configuration
// comment gives: the signing key can forge a token for every registered
// application, and a flag puts its protection in shell history.
func oidcSealKey(configPath string) (string, error) {
	if env := os.Getenv("CARDINAL_OIDC_SIGNING_KEY"); env != "" {
		return env, nil
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", fmt.Errorf("reading oidc.signing_key_encryption_key from configuration: %w", err)
	}
	if cfg.OIDC.SigningKeyEncryptionKey == "" {
		return "", errors.New(
			"oidc.signing_key_encryption_key is not set — the signing key is not " +
				"stored in the clear, so it cannot be read or rotated without it")
	}
	return cfg.OIDC.SigningKeyEncryptionKey, nil
}

func runOIDCKeyList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("oidc key list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	// VerificationKeys rather than ActiveSigningKey: this is the set a
	// receiver sees in the JWKS, and listing it needs no decryption, so
	// reading the state of the authority does not require its secret.
	keys, err := s.VerificationKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("no signing key — one is created when the provider first starts")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KEY ID\tALGORITHM\tSTATE\tCREATED") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, k := range keys {
		state := "signing"
		if k.RetiredAt != nil {
			state = "retired, still verifying"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", //nolint:errcheck // the header is already written, so the status cannot be changed
			k.KeyID, k.Algorithm, state, k.CreatedAt.Format("2006-01-02"))
	}
	return w.Flush()
}

// runOIDCKeyRotate replaces the key that signs tokens and security events.
//
// The reason this exists at all: the SSH and X.509 authorities have had rotate
// commands since they were built, and this key — which can forge a token for
// every application and sign a security event to every receiver — had none. The
// rotation was implemented, wrapped, and never given a caller.
func runOIDCKeyRotate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("oidc key rotate", flag.ContinueOnError)
	configPath := fs.String("config", "", "configuration file")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	grace := fs.Duration("grace", 0,
		"how long the previous key keeps verifying; defaults to the longest token lifetime in use")
	force := fs.Bool("force", false, "rotate even when the grace period is too short")

	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	sealKey, err := oidcSealKey(*configPath)
	if err != nil {
		return err
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	longest, err := longestTokenLifetime(ctx, s)
	if err != nil {
		return err
	}

	// The default is measured rather than assumed. The retired key must keep
	// verifying until every token signed by it has expired, and how long that
	// is depends on what the registered clients were configured with — a fixed
	// default is only ever right by accident.
	chosen := *grace
	if chosen == 0 {
		chosen = longest
	}
	if chosen < longest && !*force {
		return fmt.Errorf(
			"a grace period of %s retires the old key while tokens signed by it are "+
				"still valid — the longest token lifetime in use is %s. Pass a longer "+
				"-grace, or -force if those tokens are meant to stop verifying",
			chosen, longest)
	}

	key, err := s.RotateSigningKey(ctx, sealKey, chosen)
	if err != nil {
		return err
	}

	fmt.Printf("%s is now signing\n\n", key.KeyID)
	fmt.Printf("  The previous key stops signing and keeps verifying for %s,\n", chosen)
	fmt.Println("  so tokens issued moments ago are still accepted.")
	fmt.Println()
	fmt.Println("  Both keys are published in the JWKS. A client that caches it")
	fmt.Println("  aggressively will reject new tokens until it refetches.")
	return nil
}

// longestTokenLifetime reports how long the newest token signed now could
// remain valid.
//
// The refresh lifetime rather than the access lifetime: a refresh token
// outlives the access token it replaces, and retiring a key while one is still
// exchangeable breaks the exchange.
func longestTokenLifetime(ctx context.Context, s *store.Store) (time.Duration, error) {
	clients, err := s.ListOIDCClients(ctx)
	if err != nil {
		return 0, err
	}

	// A floor rather than zero when nothing is registered, because a key can be
	// rotated before the first client exists and a zero grace would retire the
	// old key instantly.
	longest := time.Hour
	for _, c := range clients {
		for _, d := range []time.Duration{
			c.AccessTokenLifetime, c.IDTokenLifetime, c.RefreshTokenLifetime,
		} {
			if d > longest {
				longest = d
			}
		}
	}
	return longest, nil
}
