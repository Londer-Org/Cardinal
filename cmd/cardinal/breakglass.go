package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/breakglass"
)

func runBreakGlass(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal break-glass <generate|sign>", errUsage)
	}
	switch args[0] {
	case "generate":
		return runBreakGlassGenerate(args[1:])
	case "sign":
		return runBreakGlassSign(args[1:])
	default:
		return fmt.Errorf("%w: cardinal break-glass <generate|sign>", errUsage)
	}
}

// runBreakGlassGenerate is the bootstrap ceremony.
//
// It runs entirely offline and touches neither the database nor the network.
// The private key is printed once and never written anywhere by Cardinal:
// writing it to a file would put it on a disk that gets backed up, synced, and
// eventually forgotten about, which is exactly what this design avoids.
func runBreakGlassGenerate(args []string) error {
	fs := flag.NewFlagSet("break-glass generate", flag.ContinueOnError)
	if _, err := parse(fs, args); err != nil {
		return errUsage
	}

	kp, err := breakglass.Generate()
	if err != nil {
		return err
	}

	// The private key goes to stdout and everything else to stderr, so
	// redirecting stdout onto removable media captures exactly the key and
	// nothing else.
	e := os.Stderr
	fmt.Fprintln(e, "════════════════════════════════════════════════════════════")
	fmt.Fprintln(e, "  BREAK-GLASS KEY — the credential that can do anything.")
	fmt.Fprintln(e, "  Treat this as a ceremony, not a command.")
	fmt.Fprintln(e, "════════════════════════════════════════════════════════════")
	fmt.Fprintln(e)
	fmt.Fprintln(e, "PUBLIC KEY — put this in cardinal.toml:")
	fmt.Fprintln(e)
	fmt.Fprintf(e, "  [break_glass]\n  public_key = \"%s\"\n",
		breakglass.EncodePublic(kp.Public))
	fmt.Fprintln(e)
	fmt.Fprintln(e, "  It belongs in the config file, NOT the database, so that a")
	fmt.Fprintln(e, "  database compromise cannot substitute an attacker's key and a")
	fmt.Fprintln(e, "  restore cannot silently roll it back to an older one.")
	fmt.Fprintln(e)
	fmt.Fprintln(e, "PRIVATE KEY — printed once, on stdout, and never stored:")
	fmt.Fprintln(e)

	fmt.Println(breakglass.EncodePrivate(kp.Private))

	fmt.Fprintln(e)
	fmt.Fprintln(e, "  Store it offline — printed and sealed, or on removable media in")
	fmt.Fprintln(e, "  a safe. It must NOT live on the Cardinal host, in a password")
	fmt.Fprintln(e, "  manager that authenticates through Cardinal, or in any repo.")
	fmt.Fprintln(e)
	fmt.Fprintln(e, "  At least TWO people must be able to reach it. One person holding")
	fmt.Fprintln(e, "  the only copy turns recovery into a bus-factor risk.")
	fmt.Fprintln(e)
	fmt.Fprintln(e, "  Test it quarterly. An untested emergency procedure is not a")
	fmt.Fprintln(e, "  procedure — put it on a calendar beside the restore drill.")
	fmt.Fprintln(e)

	return nil
}

// runBreakGlassSign signs a server-issued challenge.
//
// Deliberately a separate command meant to run on the operator's own machine
// with the offline key. The private key is never transmitted — the server sees
// only a signature — so nothing captured in transit, in terminal scrollback, or
// in a log can be reused.
func runBreakGlassSign(args []string) error {
	fs := flag.NewFlagSet("break-glass sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "file holding the offline private key (- for stdin)")
	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal break-glass sign <challenge> -key <file>", errUsage)
	}
	if *keyFile == "" {
		return fmt.Errorf("%w: -key is required", errUsage)
	}

	// Read the key from a file or stdin, never an argument: command-line
	// arguments are visible in `ps` output and land in shell history.
	var raw []byte
	if *keyFile == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(*keyFile) //nolint:gosec // operator-supplied path, by design
	}
	if err != nil {
		return fmt.Errorf("reading key: %w", err)
	}

	priv, err := breakglass.DecodePrivate(string(raw))
	if err != nil {
		return err
	}

	nonce, err := base64.StdEncoding.DecodeString(pos[0])
	if err != nil {
		return fmt.Errorf("decoding challenge: %w", err)
	}

	// Reconstructed locally purely to produce the signature. The server holds
	// the authoritative challenge and enforces its own expiry, so nothing here
	// can extend a challenge's lifetime.
	c := &breakglass.Challenge{
		Nonce:     nonce,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(breakglass.ChallengeTTL),
	}

	fmt.Println(c.Sign(priv))
	return nil
}
