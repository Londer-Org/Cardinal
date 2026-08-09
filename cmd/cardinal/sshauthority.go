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
	"go.londer.be/cardinal/internal/config"
	"go.londer.be/cardinal/internal/store"
)

// Administering the SSH certificate authority — `cardinal ssh ca ...`.
//
// Not to be confused with sshlogin.go, which is how a person actually logs
// into a machine. This file creates, lists, rotates and publishes the key
// that signs their certificates.

// runSSHCA administers the authority. `cardinal ssh <host>` — logging in — is
// in ssh.go and dispatches here when the first argument is `ca`.
func runSSHCA(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal ssh ca <init|list|trust|rotate>", errUsage)
	}

	switch args[0] {
	case "init":
		return runSSHCAInit(ctx, args[1:])
	case "list":
		return runSSHCAList(ctx, args[1:])
	case "trust":
		return runSSHCATrust(ctx, args[1:])
	case "rotate":
		return runSSHCARotate(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal ssh ca <init|list|trust|rotate>", errUsage)
	}
}

// sealKey resolves the CA encryption key from configuration.
//
// Read from the config file rather than a flag: it is the secret protecting the
// key that can log into every host, and a flag puts it in shell history.
func sealKey(configPath string) (string, error) {
	if env := os.Getenv("CARDINAL_SSH_CA_KEY"); env != "" {
		return env, nil
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", fmt.Errorf("reading ssh.ca_encryption_key from configuration: %w", err)
	}
	if cfg.SSH.CAEncryptionKey == "" {
		return "", errors.New(
			"ssh.ca_encryption_key is not set — the authority key is not stored in " +
				"the clear, so it cannot be created or read without it")
	}
	return cfg.SSH.CAEncryptionKey, nil
}

func runSSHCAInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssh ca init", flag.ContinueOnError)
	configPath := fs.String("config", "", "configuration file holding ssh.ca_encryption_key")
	activate := fs.Bool("activate", false,
		"start signing immediately; only safe when no host trusts an older key yet")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	seal, err := sealKey(*configPath)
	if err != nil {
		return err
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	key, err := s.CreateSSHCAKey(ctx, seal, nil)
	if err != nil {
		return err
	}

	fmt.Printf("created SSH certificate authority key\n\n")
	fmt.Printf("  id           %s\n", key.ID)
	fmt.Printf("  fingerprint  %s\n\n", key.Fingerprint)
	fmt.Printf("%s\n", key.PublicKey)

	if *activate {
		if err := s.ActivateSSHCAKey(ctx, key.ID, 48*time.Hour, nil); err != nil {
			return err
		}
		fmt.Println("  Signing immediately, because -activate was given.")
		fmt.Println()
	} else {
		// The default, and the safe order. A key that signs before the fleet
		// trusts it issues certificates every host rejects, which looks like
		// Cardinal being broken rather than a procedure being run backwards.
		fmt.Println("  Not signing yet. Distribute the public key above to every host")
		fmt.Println("  first, then run `cardinal ssh ca rotate " + key.ID.String() + "`.")
		fmt.Println()
	}

	fmt.Println("  Hosts running cardinal-agent pick this up on their own: the trusted")
	fmt.Println("  authorities ride the assignment they already poll, so a rotation")
	fmt.Println("  reaches the fleet within one interval and needs no fleet-wide step.")
	fmt.Println()
	fmt.Println("  For a host without the agent, in /etc/ssh/sshd_config:")
	fmt.Println("    TrustedUserCAKeys /etc/ssh/cardinal_ca.pub")
	fmt.Println()
	fmt.Println("  `cardinal ssh ca trust` prints the file's full contents, including")
	fmt.Println("  any retired key still inside its grace period.")
	return nil
}

func runSSHCAList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssh ca list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	keys, err := s.TrustedSSHCAKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("no SSH certificate authority key — create one with `cardinal ssh ca init`")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tFINGERPRINT\tSTATE\tTRUSTED UNTIL") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, k := range keys {
		state := "published"
		switch {
		case k.Signing():
			state = "signing"
		case k.RetiredAt != nil:
			state = "retired"
		}
		until := "—"
		if k.ValidUntil != nil {
			until = k.ValidUntil.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", k.ID, k.Fingerprint, state, until) //nolint:errcheck // the header is already written, so the status cannot be changed
	}
	return w.Flush()
}

func runSSHCATrust(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssh ca trust", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	keys, err := s.TrustedSSHCAKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("no SSH certificate authority key exists")
	}

	// Every currently-trusted key, signing or not. A host trusting only the
	// signing key rejects every certificate issued in the minutes before a
	// rotation, which is the failure this file exists to avoid.
	for _, k := range keys {
		fmt.Print(k.PublicKey)
	}
	return nil
}

func runSSHCARotate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("ssh ca rotate", flag.ContinueOnError)
	configPath := fs.String("config", "", "configuration file")
	grace := fs.Duration("grace", 48*time.Hour,
		"how long the previous key stays trusted after it stops signing")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal ssh ca rotate <key-id>", errUsage)
	}
	keyID, err := uuid.Parse(pos[0])
	if err != nil {
		return fmt.Errorf("%q is not a key id — see `cardinal ssh ca list`", pos[0])
	}
	if _, sealKeyErr := sealKey(*configPath); sealKeyErr != nil {
		return sealKeyErr
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.ActivateSSHCAKey(ctx, keyID, *grace, nil); err != nil {
		if errors.Is(err, store.ErrNoSSHCA) {
			return fmt.Errorf("no such key %s, or it is already retired", keyID)
		}
		return err
	}

	fmt.Printf("%s is now signing\n\n", keyID)
	fmt.Printf("  The previous key stops signing now and stays trusted for %s,\n", *grace)
	fmt.Println("  so certificates issued moments ago keep working.")
	fmt.Println()
	fmt.Println("  Hosts running cardinal-agent converge on their own — the trusted")
	fmt.Println("  authorities ride the assignment they already poll. Until a host has")
	fmt.Println("  fetched, it rejects certificates signed by the new key, so the window")
	fmt.Println("  to watch is one refresh interval rather than however long a fleet-wide")
	fmt.Println("  copy takes.")
	fmt.Println()
	fmt.Println("  For hosts without the agent, `cardinal ssh ca trust` prints what has")
	fmt.Println("  to reach them, and it has to reach them now rather than before the")
	fmt.Println("  grace period ends: the new key is already signing.")
	return nil
}
