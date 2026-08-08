package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

func runToken(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal token <create|list|revoke>", errUsage)
	}
	switch args[0] {
	case "create":
		return runTokenCreate(ctx, args[1:])
	case "list":
		return runTokenList(ctx, args[1:])
	case "revoke":
		return runTokenRevoke(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal token <create|list|revoke>", errUsage)
	}
}

func runTokenCreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	name := fs.String("name", "", "what the token is for (required)")
	// Bounded by default, like a membership grant. A credential nobody chose an
	// end date for is one nobody will remember to withdraw.
	ttl := fs.Duration("for", 90*24*time.Hour, "how long it stays valid")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal token create <login> -name <text>", errUsage)
	}
	if *name == "" {
		return fmt.Errorf("%w: -name is required", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, directory.TypeUser, pos[0])
	if err != nil {
		return fmt.Errorf("no such user %q", pos[0])
	}

	token, err := s.CreateAccessToken(ctx, entity.ID, *name, *ttl, nil)
	if err != nil {
		return err
	}

	fmt.Printf("access token for %s\n\n  %s\n\n", entity.Name, token.Token)
	fmt.Printf("  name     %s\n", token.Name)
	fmt.Printf("  expires  %s\n\n", token.ValidUntil.Format(time.RFC3339))
	fmt.Println("  Shown once and not recoverable — only its hash is stored.")
	fmt.Println("  Send it as `Authorization: Bearer <token>`.")
	fmt.Println()
	fmt.Println("  It authenticates as this account but is never device-bound, so")
	fmt.Println("  policy refuses it administrative actions and SSH certificates.")
	fmt.Println("  Revoke with `cardinal token revoke " + entity.Name + " <id>`.")
	return nil
}

func runTokenList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal token list <login>", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, directory.TypeUser, pos[0])
	if err != nil {
		return fmt.Errorf("no such user %q", pos[0])
	}

	tokens, err := s.ListAccessTokens(ctx, entity.ID)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		fmt.Printf("%s has no access tokens\n", entity.Name)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tPREFIX\tEXPIRES\tLAST USED")
	for _, t := range tokens {
		state := t.ValidUntil.Format("2006-01-02")
		if t.Expired() {
			state += " (ended)"
		}
		lastUsed := "never"
		if t.LastUsedAt != nil {
			lastUsed = t.LastUsedAt.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(w, "%s\t%s\t%s…\t%s\t%s\n",
			t.ID, t.Name, t.Prefix, state, lastUsed)
	}
	return w.Flush()
}

func runTokenRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("token revoke", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		return fmt.Errorf("%w: cardinal token revoke <login> <token-id>", errUsage)
	}

	tokenID, err := uuid.Parse(pos[1])
	if err != nil {
		return fmt.Errorf("%q is not a token id — see `cardinal token list %s`", pos[1], pos[0])
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, directory.TypeUser, pos[0])
	if err != nil {
		return fmt.Errorf("no such user %q", pos[0])
	}

	if err := s.RevokeAccessToken(ctx, tokenID, entity.ID, nil); err != nil {
		if errors.Is(err, store.ErrNoSuchToken) {
			return fmt.Errorf("no live token %s for %s", tokenID, entity.Name)
		}
		return err
	}

	fmt.Printf("revoked %s\n", tokenID)
	fmt.Println("  The row survives, with its window closed — an audit that cannot")
	fmt.Println("  see a withdrawn credential cannot say what it did while it worked.")
	return nil
}
