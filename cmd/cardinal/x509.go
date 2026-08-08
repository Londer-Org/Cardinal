package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/config"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/store"
)

func runX509(ctx context.Context, args []string) error {
	usage := fmt.Errorf("%w: cardinal x509 ca <init|list|trust|rotate>", errUsage)
	if len(args) < 2 || args[0] != "ca" {
		return usage
	}

	switch args[1] {
	case "init":
		return runX509Init(ctx, args[2:])
	case "list":
		return runX509List(ctx, args[2:])
	case "trust":
		return runX509Trust(ctx, args[2:])
	case "rotate":
		return runX509Rotate(ctx, args[2:])
	default:
		return usage
	}
}

// x509SealKey resolves the authority's encryption key.
//
// From configuration rather than a flag, like the SSH authority: it is the
// secret protecting the key that can issue a certificate for any name the fleet
// trusts, and a flag puts it in shell history.
func x509SealKey(configPath string) (string, error) {
	if env := os.Getenv("CARDINAL_X509_CA_KEY"); env != "" {
		return env, nil
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", fmt.Errorf("reading x509.ca_encryption_key from configuration: %w", err)
	}
	if cfg.X509.CAEncryptionKey == "" {
		return "", errors.New(
			"x509.ca_encryption_key is not set — the authority key is not stored " +
				"in the clear, so it cannot be created or read without it")
	}
	return cfg.X509.CAEncryptionKey, nil
}

func runX509Init(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("x509 ca init", flag.ContinueOnError)
	configPath := fs.String("config", "", "configuration file holding x509.ca_encryption_key")
	subject := fs.String("subject", "", "the authority's common name")
	validity := fs.Duration("for", store.DefaultRootValidity, "how long the authority lasts")
	activate := fs.Bool("activate", false,
		"start signing immediately; only safe when nothing trusts an older key yet")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	if _, err := parse(fs, args); err != nil {
		return errUsage
	}
	if *subject == "" {
		return fmt.Errorf("%w: -subject is required, e.g. -subject 'Example Internal CA'",
			errUsage)
	}

	seal, err := x509SealKey(*configPath)
	if err != nil {
		return err
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	key, err := s.CreateX509CAKey(ctx, seal, *subject, *validity, nil)
	if err != nil {
		return err
	}

	fmt.Printf("created X.509 certificate authority\n\n")
	fmt.Printf("  id           %s\n", key.ID)
	fmt.Printf("  subject      %s\n", key.Subject)
	fmt.Printf("  fingerprint  %s\n", key.Fingerprint)
	fmt.Printf("  expires      %s\n\n", key.NotAfter.Format(time.RFC3339))

	if *activate {
		if err := s.ActivateX509CAKey(ctx, key.ID, nil); err != nil {
			return err
		}
		fmt.Println("  Signing immediately, because -activate was given.")
	} else {
		fmt.Println("  Not signing yet. Distribute the certificate first —")
		fmt.Printf("  `cardinal x509 ca trust` — then `cardinal x509 ca rotate %s`.\n", key.ID)
	}

	fmt.Fprintln(os.Stderr,
		"\n  Getting this into every trust store is the part that takes the time,\n"+
			"  and no amount of software does it for you: system stores, container\n"+
			"  images, JVM keystores, browsers. An internal CA is worthless until\n"+
			"  that is done, and it is the reason people give up on one.")
	return nil
}

func runX509List(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("x509 ca list", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	keys, err := s.TrustedX509CAKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Println("no X.509 authority — create one with `cardinal x509 ca init`")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSUBJECT\tSTATE\tEXPIRES")
	for _, k := range keys {
		state := "published"
		switch {
		case k.Signing():
			state = "signing"
		case k.RetiredAt != nil:
			state = "retired"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			k.ID, k.Subject, state, k.NotAfter.Format("2006-01-02"))
	}
	return w.Flush()
}

// runX509Trust prints what has to reach every trust store.
func runX509Trust(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("x509 ca trust", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	keys, err := s.TrustedX509CAKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("no X.509 authority exists")
	}

	// Every trusted key, signing or not — the same rule as the SSH authority's
	// TrustedUserCAKeys file. A trust store holding only the signing key
	// rejects every certificate issued in the minutes before a rotation.
	for _, k := range keys {
		if err := pem.Encode(os.Stdout, &pem.Block{
			Type: "CERTIFICATE", Bytes: k.Certificate.Raw,
		}); err != nil {
			return err
		}
	}
	return nil
}

func runX509Rotate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("x509 ca rotate", flag.ContinueOnError)
	configPath := fs.String("config", "", "configuration file")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal x509 ca rotate <key-id>", errUsage)
	}
	id, err := uuid.Parse(pos[0])
	if err != nil {
		return fmt.Errorf("%q is not a key id — see `cardinal x509 ca list`", pos[0])
	}
	if _, err := x509SealKey(*configPath); err != nil {
		return err
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.ActivateX509CAKey(ctx, id, nil); err != nil {
		return err
	}

	fmt.Printf("%s is now signing\n\n", id)
	fmt.Println("  The previous key stops signing and stays trusted until it expires,")
	fmt.Println("  so certificates issued moments ago keep working.")
	return nil
}

// runACMECredentials issues an external account binding for a host.
//
// The credential a machine needs before any ACME client can do anything, and
// the thing that turns an anonymous ACME account into one belonging to a
// specific host.
func runACMECredentials(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("host acme-credentials", flag.ContinueOnError)
	configPath := fs.String("config", "", "configuration file")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal host acme-credentials <name>", errUsage)
	}

	seal, err := x509SealKey(*configPath)
	if err != nil {
		return err
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	host, err := s.LookupEntity(ctx, directory.TypeHost, pos[0])
	if err != nil {
		return fmt.Errorf("no such host %q", pos[0])
	}

	names, err := s.HostPrincipals(ctx, host.ID)
	if err != nil {
		return err
	}

	credential, err := s.CreateEABCredential(ctx, host.ID, seal, nil)
	if err != nil {
		return err
	}

	fmt.Printf("kid   %s\n", credential.KeyID)
	fmt.Printf("hmac  %s\n", credential.HMACKey)

	fmt.Fprintf(os.Stderr,
		"\n  For %s, valid until %s. Single use: creating the account spends it.\n",
		host.Name, credential.ExpiresAt.Local().Format(time.RFC1123))
	fmt.Fprintf(os.Stderr,
		"\n  It may then order certificates for exactly these names:\n")
	for _, name := range names {
		fmt.Fprintf(os.Stderr, "    %s\n", name)
	}
	fmt.Fprintln(os.Stderr,
		"\n  Anything else is refused — the CSR does not decide, the directory does.\n"+
			"  Grant another with `cardinal host alias add`.")
	return nil
}
