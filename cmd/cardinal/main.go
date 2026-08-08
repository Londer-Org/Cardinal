// Command cardinal is the administrative CLI for a Cardinal directory.
//
// It is deliberately built on the standard library's flag package rather than a
// CLI framework: Cardinal is security infrastructure, and every dependency is
// something to audit and keep patched. The ergonomics of a framework do not yet
// justify that cost.
package main

import (
	"context"
	"errors"
	"fmt"
	"go.londer.be/cardinal/internal/version"
	"os"
	"os/signal"
	"syscall"

	"github.com/BurntSushi/toml"
)

const defaultDSN = "postgres://cardinal:cardinal@localhost:5433/cardinal?sslmode=disable"

func main() {
	// Cancel on SIGINT/SIGTERM so an interrupted command rolls its transaction
	// back rather than leaving one open until the connection is reaped.
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		// A bare errUsage means usage() was already printed; anything wrapping
		// it carries a specific message that must still reach the user.
		if !errors.Is(err, errBareUsage) {
			fmt.Fprintf(os.Stderr, "cardinal: %v\n", err)
		}
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

var (
	errUsage = errors.New("usage")
	// errBareUsage marks the case where full usage text has already been
	// printed, so main should not also print a one-line message.
	errBareUsage = fmt.Errorf("%w: printed", errUsage)
)

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return errBareUsage
	}

	cmd, rest := args[0], args[1:]

	switch cmd {
	case "host":
		return runHost(ctx, rest)
	case "user", "group", "service-account", "application", "device", "role":
		return runEntityCommand(ctx, cmd, rest)
	case "list":
		return runList(ctx, rest)
	case "show":
		return runShow(ctx, rest)
	case "grant":
		return runGrant(ctx, rest)
	case "revoke":
		return runRevoke(ctx, rest)
	case "members":
		return runMembers(ctx, rest)
	case "memberships":
		return runMemberships(ctx, rest)
	case "history":
		return runHistory(ctx, rest)
	case "init":
		return runInit(ctx, args[1:])
	case "version":
		fmt.Println(version.String())
		return nil
	case "migrate":
		return runMigrate(ctx, rest)
	case "invite":
		return runInvite(ctx, args[1:])
	case "app":
		return runApp(ctx, rest)
	case "token":
		return runToken(ctx, rest)
	case "ssh":
		return runSSH(ctx, rest)
	case "posix":
		return runPOSIX(ctx, rest)
	case "x509":
		return runX509(ctx, rest)
	case "policy":
		return runPolicy(ctx, rest)
	case "serve":
		return runServe(ctx, rest)
	case "redact":
		return runRedact(ctx, rest)
	case "audit":
		return runAudit(ctx, rest)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "cardinal: unknown command %q\n\n", cmd)
		usage()
		return errBareUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cardinal — administer a Cardinal directory

USAGE
  cardinal <command> [arguments]

SERVER
  migrate [-status]                         Apply the embedded schema
  init <login> [-display <text>]            First-run setup: policy, the first
                                            administrator, and an enrollment link
  serve [-config <file>] [-dev]             Run the API and admin UI

ENTITIES
  user create <name> [-display <text>]     Create a user
  group create <name> [-display <text>]    Create a group
  host create <name> [-display <text>]     Create a host
  <type> disable <name>                    Cut an account off. Sessions and
                                           access tokens are revoked with it.
  <type> enable <name>                     Undo that. History is kept either
                                           way — nothing here is a delete.
  list [type] [-all]                       List entities (-all includes disabled)
  show <type> <name>                       Show one entity and its memberships

ENROLLMENT
  invite <login> [-for <duration>]         Print a single-use enrollment link
  invite list                              Outstanding invitations
  invite revoke <login>                    Withdraw one

MEMBERSHIP
  grant <group> <member> [flags]           Grant membership
      -for <duration>                        e.g. 72h — bounded, and preferred
      -until <RFC3339>                       explicit end instant
      -reason <text>                         why, preserved even after revocation
  revoke <group> <member> [-at <RFC3339>]  End a membership, keeping its history
  members <group> [-at <RFC3339>]          Who is in a group, now or at an instant
  memberships <user> [-at <RFC3339>]       Which groups someone is in, transitively
  history <group> <member>                 Every grant ever, including expired

PRIVACY
  redact <type> <name> [-yes]              Erase personal data (GDPR Art. 17).
                                           Membership history and the audit
                                           chain survive; attribution does not.

APPLICATIONS (OpenID Connect)
  app register <name> -redirect <uri>       Register a relying party
  app list                                  Registered applications

ACCESS TOKENS (scripts and automation)
  token create <login> -name <text>         Issue a bearer token, shown once
      -for <duration>                         default 90d; bounded like a grant
  token list <login>                        Tokens, live ones first
  token revoke <login> <token-id>           End one, keeping its history

  A token authenticates its owner but is never device-bound, so existing policy
  refuses it administrative actions and SSH certificates.

HOST ACCESS (SSH certificates)
  ssh ca init [-activate]                  Create an authority key, print its
                                           public half for TrustedUserCAKeys
  ssh ca list                              Keys, and which one is signing
  ssh ca trust                             The full TrustedUserCAKeys contents
  ssh ca rotate <key-id> [-grace <dur>]    Make a key sign; the previous one
                                           stays trusted for the grace period

POSIX IDENTITY (uid and gid numbers)
  posix assign <user|group> <name>         Hand out the next number. Permanent:
                                           every file on disk records it, so
                                           there is no way to change or release
                                           one afterwards.
  posix show <user|group> <name>           The passwd or group line
  posix set <user> [-home] [-shell]        Change where a login lands
  posix list                               Every number handed out
  posix adopt <user> <number>              Take a number a machine already uses
  posix adopt -from <report.json,...>      The same, from the output of
                                           cardinal-agent shadow -json. Shows
                                           the changes; -yes applies them.
                                           Refused once a number has been served
                                           to a host: it is on a filesystem by
                                           then, and changing it moves files
                                           rather than editing a row.

HOSTS (a machine proving which host it is)
  host enroll <name>                       Print the join command for a machine.
                                           Single use, expires in an hour.
  host credentials <name>                  Keys this host has enrolled with
  host join -server <url> -token <tok>     Run on the machine. Generates its key
                                           and registers the public half.
  host whoami -server <url>                Ask Cardinal who this machine is
  host alias list <host>                   Names this machine may prove
  host alias add <host> <name>             Grant another name. Unique across
                                           the fleet: two machines answering to
                                           one name is the ambiguity host
                                           certificates exist to remove.
  host alias remove <host> <name>          Withdraw one
  host acme-credentials <host>             Issue an ACME external account
                                           binding, so this machine can order
                                           X.509 certificates for its names

CERTIFICATE AUTHORITY (X.509, over ACME)
  x509 ca init -subject <name>             Create an authority. Not signing
                                           until distributed and rotated to.
  x509 ca list                             Keys, and which one is signing
  x509 ca trust                            Every trusted certificate, PEM —
                                           what has to reach every trust store
  x509 ca rotate <key-id>                  Make a key sign

  Clients point at <public-url>/acme/directory and speak RFC 8555. Nothing is
  issued for a name the directory has not granted, whatever the CSR asks for.

  join and whoami run on the host and never touch the database. Everything else
  here is administration and does.

AUTHORIZATION
  policy test <file.cedar>                 Compile a policy file (offline)
  policy publish <file> [-activate]        Store a new version
  policy activate <version>                Make a version live (rollback too)
  policy list                              Published versions
  policy show                              The live policy set

AUDIT
  audit verify                             Verify the event log's hash chain

GLOBAL
  -dsn <url>    PostgreSQL connection string
                (or set CARDINAL_DSN; defaults to the local dev database)

Grants should normally be bounded. Whoever asks for access almost always knows
when they will stop needing it, and a bounded grant cannot be forgotten.
`)
}

// dsn resolves the connection string.
//
// Order: explicit flag, then CARDINAL_DSN, then the configuration file, then
// the development default.
//
// Reading the config file matters more than it looks. Without it, an operator
// who has mounted cardinal.toml into a container still has to repeat -dsn on
// every administrative command — and the DSN contains a password, so they end
// up putting a credential in their shell history to run `cardinal list`.
func dsn(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("CARDINAL_DSN"); env != "" {
		return env
	}
	if fromConfig := dsnFromConfig(); fromConfig != "" {
		return fromConfig
	}
	return defaultDSN
}

// configSearchPaths are tried in order. The container path comes first because
// that is where a deployment mounts it, and a stray cardinal.toml in the
// working directory should not silently win over the mounted one.
var configSearchPaths = []string{
	"/etc/cardinal/cardinal.toml",
	"cardinal.toml",
}

// dsnFromConfig reads just the DSN, tolerating a config that is otherwise
// incomplete.
//
// config.Load validates everything and refuses a file missing, say, the
// WebAuthn origins — correct for starting a server, wrong here. `cardinal
// migrate` must work against a half-configured deployment, since applying the
// schema is often the first thing done.
func dsnFromConfig() string {
	paths := configSearchPaths
	if env := os.Getenv("CARDINAL_CONFIG"); env != "" {
		paths = append([]string{env}, paths...)
	}

	for _, path := range paths {
		var partial struct {
			Database struct {
				DSN string `toml:"dsn"`
			} `toml:"database"`
		}
		if _, err := toml.DecodeFile(path, &partial); err == nil && partial.Database.DSN != "" {
			return partial.Database.DSN
		}
	}
	return ""
}
