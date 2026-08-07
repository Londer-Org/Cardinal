package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/directory"
	"github.com/arthur-lonfils/cardinal/internal/hostclient"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"golang.org/x/crypto/ssh"
)

// runHost keeps `cardinal host create` where every other entity type has it and
// adds the two verbs only a host has: handing a machine a way in, and seeing
// which key it came in with.
func runHost(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal host "+
			"<create|enroll|join|whoami|credentials|alias|acme-credentials>", errUsage)
	}
	switch args[0] {
	case "enroll":
		return runHostEnroll(ctx, args[1:])
	case "join":
		return runHostJoin(ctx, args[1:])
	case "whoami":
		return runHostWhoami(ctx, args[1:])
	case "credentials":
		return runHostCredentials(ctx, args[1:])
	case "alias":
		return runHostAlias(ctx, args[1:])
	case "acme-credentials":
		return runACMECredentials(ctx, args[1:])
	default:
		return runEntityCommand(ctx, "host", args)
	}
}

// runHostEnroll prints the command to run on the machine.
//
// Not just the token. An operator holding a bare secret still has to know what
// to do with it, and the step they get wrong is generating the keypair — either
// by reusing the machine's SSH host key, which is a key that already has another
// job, or by generating it somewhere other than the machine, which defeats the
// point of Cardinal never holding it.
//
// The whole line goes to stdout so it can be piped into a console. Everything
// explanatory goes to stderr, following `cardinal invite`.
func runHostEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("host enroll", flag.ContinueOnError)
	baseURL := fs.String("url", "",
		"public base URL of this Cardinal, if it differs from the config")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	configPath := fs.String("config", "", "configuration file, for the public URL")
	tokenOnly := fs.Bool("token", false, "print only the token")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal host enroll <name>", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, directory.TypeHost, pos[0])
	if err != nil {
		return fmt.Errorf("no such host %q — create it first with `cardinal host create %s`",
			pos[0], pos[0])
	}

	existing, err := s.ListHostCredentials(ctx, entity.ID)
	if err != nil {
		return err
	}

	// Issued by nobody, for the same reason invitations are: the CLI reaches the
	// database directly, and naming an actor who did not authenticate would make
	// the journal say something untrue.
	enrollment, err := s.CreateHostEnrollment(ctx, entity.ID, nil)
	if err != nil {
		return err
	}

	if *tokenOnly {
		fmt.Println(enrollment.Token)
		return nil
	}

	base := *baseURL
	if base == "" {
		if cfg, err := loadConfigForCheck(*configPath); err == nil {
			base = cfg.Server.PublicURL
		}
	}
	if base == "" {
		base = "http://localhost:8099"
		fmt.Fprintf(os.Stderr,
			"  Note: no public URL was readable, so the command below assumes %s.\n"+
				"  Pass -url if that is wrong.\n\n", base)
	}
	base = strings.TrimRight(base, "/")

	if len(existing) > 0 {
		fmt.Fprintf(os.Stderr,
			"  Note: %s has enrolled before. Redeeming this retires the key it uses\n"+
				"  now, so run it on the machine itself and not as a rehearsal.\n\n",
			entity.Name)
	}

	fmt.Fprintf(os.Stderr, "  enrollment for %s, valid until %s\n\n",
		entity.Name, enrollment.ExpiresAt.Local().Format(time.RFC1123))

	fmt.Fprintln(os.Stderr, "  Run this on the machine:")
	fmt.Fprintln(os.Stderr)

	fmt.Printf("cardinal host join -server %s -token %s\n", base, enrollment.Token)

	fmt.Fprintf(os.Stderr,
		"\n  Single use, and it expires in %s. The agent generates its own keypair\n"+
			"  and sends only the public half, so Cardinal never holds a key that\n"+
			"  could impersonate this host.\n", store.HostEnrollmentTTL)
	return nil
}

func runHostCredentials(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("host credentials", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")

	pos, err := parse(fs, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 1 {
		return fmt.Errorf("%w: cardinal host credentials <name>", errUsage)
	}

	s, err := open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	entity, err := s.LookupEntity(ctx, directory.TypeHost, pos[0])
	if err != nil {
		return fmt.Errorf("no such host %q", pos[0])
	}

	creds, err := s.ListHostCredentials(ctx, entity.ID)
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		fmt.Printf("%s has never enrolled — issue a token with `cardinal host enroll %s`\n",
			entity.Name, entity.Name)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FINGERPRINT\tSTATE\tENROLLED\tLAST SEEN")
	for _, c := range creds {
		seen := "never"
		if c.LastSeenAt != nil {
			seen = c.LastSeenAt.Local().Format(time.RFC3339)
		}
		state := "retired"
		if c.Live {
			state = "live"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Fingerprint, state,
			c.EnrolledAt.Local().Format(time.RFC3339), seen)
	}
	return w.Flush()
}

// runHostJoin is the machine's side, and the only command here that does not
// touch the database.
//
// Deliberately in the same binary rather than waiting for cardinal-agent. A host
// must be able to enrol before anything is installed on it — that is the whole
// bootstrapping problem — and an operator who can copy one static binary onto a
// machine should not also need a package repository to get started.
func runHostJoin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("host join", flag.ContinueOnError)
	server := fs.String("server", "", "base URL of the Cardinal server")
	token := fs.String("token", "", "enrollment token from `cardinal host enroll`")
	keyPath := fs.String("key", hostclient.DefaultKeyPath, "where to write this host's key")

	if _, err := parse(fs, args); err != nil {
		return errUsage
	}
	if *server == "" || *token == "" {
		return fmt.Errorf("%w: cardinal host join -server <url> -token <token>", errUsage)
	}

	// Generated before the request, not after: the token is spent by the server
	// the instant it is accepted, so a key created afterwards could not be
	// registered without issuing another one.
	signer, err := hostclient.GenerateKey(*keyPath)
	if err != nil {
		return err
	}

	name, err := hostclient.Enroll(ctx, http.DefaultClient, *server, *token, signer.PublicKey())
	if err != nil {
		// The key is useless now — it was never registered, and leaving it
		// behind would make the next attempt fail on O_EXCL with a confusing
		// message about a key this host does not really have.
		_ = os.Remove(*keyPath)
		return err
	}

	fmt.Printf("enrolled as %s\n\n", name)
	fmt.Printf("  key          %s\n", *keyPath)
	fmt.Printf("  fingerprint  %s\n\n", ssh.FingerprintSHA256(signer.PublicKey()))
	fmt.Println("  Back it up or don't — either is defensible. Losing it costs one")
	fmt.Println("  `cardinal host enroll` and nothing else, which is why there is no")
	fmt.Println("  recovery path for it.")
	return nil
}

// runHostWhoami asks Cardinal who this machine is.
//
// The smallest possible check that enrollment worked: it signs a real request
// with the real key against the real server, so if it answers, every part of the
// path is sound.
func runHostWhoami(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("host whoami", flag.ContinueOnError)
	server := fs.String("server", "", "base URL of the Cardinal server")
	keyPath := fs.String("key", hostclient.DefaultKeyPath, "this host's key")

	if _, err := parse(fs, args); err != nil {
		return errUsage
	}
	if *server == "" {
		return fmt.Errorf("%w: cardinal host whoami -server <url>", errUsage)
	}

	signer, err := hostclient.LoadKey(*keyPath)
	if err != nil {
		return err
	}
	identity := &hostclient.Identity{Server: *server, Signer: signer}

	resp, err := identity.Do(ctx, http.DefaultClient, http.MethodGet, "/api/hosts/me", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cardinal did not recognise this host: %s", resp.Status)
	}

	var out struct {
		Host   string   `json:"host"`
		HostID string   `json:"hostId"`
		Groups []string `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}

	fmt.Printf("%s\n\n", out.Host)
	fmt.Printf("  id           %s\n", out.HostID)
	fmt.Printf("  fingerprint  %s\n", identity.Fingerprint())
	if len(out.Groups) == 0 {
		fmt.Println("  groups       none — no policy that names a group will match this host")
	} else {
		fmt.Printf("  groups       %s\n", strings.Join(out.Groups, ", "))
	}
	return nil
}

// runHostAlias manages the extra names a machine may prove.
//
// Its own verb rather than a flag on `host create`, because granting a name is a
// separate decision from creating a machine and is made later, by somebody
// thinking about DNS rather than about inventory.
func runHostAlias(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal host alias <list|add|remove> <host> [name]", errUsage)
	}

	fs := flag.NewFlagSet("host alias", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return errUsage
	}

	verb := args[0]
	if verb != "list" && verb != "add" && verb != "remove" {
		return fmt.Errorf("%w: cardinal host alias <list|add|remove>", errUsage)
	}
	want := 2
	if verb == "list" {
		want = 1
	}
	if len(pos) != want {
		return fmt.Errorf("%w: cardinal host alias %s <host>%s", errUsage, verb,
			map[bool]string{true: "", false: " <name>"}[verb == "list"])
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

	switch verb {
	case "list":
		principals, err := s.HostPrincipals(ctx, host.ID)
		if err != nil {
			return err
		}
		for i, name := range principals {
			if i == 0 {
				fmt.Printf("%s\t(directory name)\n", name)
				continue
			}
			fmt.Println(name)
		}
		return nil

	case "add":
		if err := s.AddHostAlias(ctx, host.ID, pos[1], nil); err != nil {
			if errors.Is(err, store.ErrNameTaken) {
				fmt.Fprintln(os.Stderr,
					"\n  Two machines answering to one name is the ambiguity host\n"+
						"  certificates exist to remove.")
				return err
			}
			return err
		}
		fmt.Printf("%s may now prove it is %s\n", host.Name, pos[1])
		fmt.Fprintln(os.Stderr,
			"\n  Takes effect when the agent next renews its certificate, which is\n"+
				"  within a third of the certificate's life rather than immediately.")
		return nil

	default:
		if err := s.RemoveHostAlias(ctx, host.ID, pos[1], nil); err != nil {
			return err
		}
		fmt.Printf("%s no longer holds %s\n", host.Name, pos[1])
		fmt.Fprintln(os.Stderr,
			"\n  The certificate already issued keeps working until it expires —\n"+
				"  there is no revocation list, which is why they are measured in days.")
		return nil
	}
}
