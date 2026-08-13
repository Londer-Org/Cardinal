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
	"os"
	"os/signal"
	"syscall"

	"go.londer.be/cardinal/internal/cli/command"
	"go.londer.be/cardinal/internal/version"
)

func main() {
	// os.Exit is the last thing that happens, and nothing is deferred in this
	// frame. Exiting from inside main while a `defer stop()` was pending meant
	// the signal handler was never unregistered — harmless at process death,
	// but it is the same mistake that silently skips a flush or a rollback, so
	// the shape is worth not having.
	os.Exit(cardinal())
}

// cardinal runs the CLI and returns the process exit code.
func cardinal() int {
	// Cancel on SIGINT/SIGTERM so an interrupted command rolls its transaction
	// back rather than leaving one open until the connection is reaped.
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := run(ctx, os.Args[1:])
	if err == nil {
		return 0
	}

	// A bare errUsage means usage() was already printed; anything wrapping
	// it carries a specific message that must still reach the user.
	if !errors.Is(err, errBareUsage) {
		fmt.Fprintf(os.Stderr, "cardinal: %v\n", err)
	}
	if errors.Is(err, errUsage) {
		return 2
	}
	return 1
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
		return client(ctx, rest, command.Entity(cmd))
	case "list":
		return runList(ctx, rest)
	case "show":
		return runShow(ctx, rest)
	// Membership goes through the API (ADR 0033): these sign in rather than
	// opening the database, so policy governs both what they may see and what
	// they may change, and the journal names the person rather than the path.
	//
	// Granting this way requires a device-bound credential used minutes ago,
	// which no unattended process can produce. That is deliberate, and it is
	// the reason this repository's own end-to-end fixtures mint a session
	// against the database and call the API with it rather than granting
	// through the CLI: the escape hatch for automation is the connection
	// string, which is already the thing that owns the directory outright.
	case "grant":
		return client(ctx, rest, command.Grant)
	case "revoke":
		return client(ctx, rest, command.Revoke)
	case "members":
		return client(ctx, rest, command.Members)
	case "memberships":
		return client(ctx, rest, command.Memberships)
	case "history":
		return client(ctx, rest, command.History)
	case "version":
		fmt.Println(version.String())
		return nil
	case "invite":
		return runInvite(ctx, args[1:])
	case "app":
		return runApp(ctx, rest)
	case "token":
		return runToken(ctx, rest)
	case "mail":
		return runMail(ctx, rest)
	case "ssh":
		return runSSH(ctx, rest)
	case "ssf":
		return runSSF(ctx, rest)
	case "posix":
		return runPOSIX(ctx, rest)
	case "x509":
		return runX509(ctx, rest)
	case "oidc":
		return runOIDC(ctx, rest)
	case "policy":
		return runPolicy(ctx, rest)
	case "decisions":
		return runDecisions(ctx, rest)
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

RUNNING IT
  Running the server, applying the schema and first-run setup are
  cardinal-server, which is a separate binary and the one a deployment
  carries. This one administers a Cardinal that is already running, and is
  deliberately not in the container image — a shell there should not come with
  an administrative tool attached.

ENTITIES
  user create <name> [-display <text>]     Create a user
      -invite                                and print an enrolment link now,
                                             rather than as a second command
  group create <name> [-display <text>]    Create a group
      -app <application>                     the application it exists for, so
                                             that application is told about it
  host create <name> [-display <text>]     Create a host
  application create <name>                Create an application, for one behind
                                           a proxy: no OIDC registration needed
  service-account create <name>            Create a machine identity
  device create <name>                     Types the model allows and little
  role create <name>                       uses; here because they dispatch
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
      -at <RFC3339>                          answer for one instant instead:
                                             was this member in this group then

PRIVACY
  redact <type> <name> [-yes]              Erase personal data (GDPR Art. 17).
                                           Membership history and the audit
                                           chain survive; attribution does not.

APPLICATIONS
  app register <name> -redirect <uri>       Register an OIDC relying party
  app list                                  Registered relying parties

  app hostname add <app> <hostname>         Which address this application
                                            answers to, so forwardAuth can find
                                            it. One application per hostname.
  app hostname remove <app> <hostname>      Withdraw one. Effective immediately:
                                            forwardAuth asks on every request.
  app hostname list [app]                   Every mapping, or one application's

  app groups show <app>                     Which groups this application is
                                            told about, and why each one.
  app groups mode <app> <owned|all>         owned tells it the groups it owns;
                                            all tells it every group a person
                                            belongs to, which is what every
                                            application saw before this existed.
  app groups allow <app> <group>            Tell it about a group it does not
  app groups disallow <app> <group>         own, or stop.

  A projection changes what an application is *told*, never what Cardinal
  decides — policy is evaluated against the full membership either way.

  An application behind a proxy needs no OIDC client — cardinal application
  create <name>, plus a hostname, is enough. A hostname nothing claims is
  refused before policy is consulted, like an SSH certificate for a machine
  nobody enrolled.

  Registering makes an application findable, not reachable. What makes it
  reachable is a group the policy set names — for the shipped rule, that is
  cardinal grant staff-apps <app>.

ACCESS TOKENS (scripts and automation)
  token create <login> -name <text> -scope <a>,<b>
                                            Issue a bearer token, shown once
      -scope                                  required: identity, applications,
                                              profile, decisions, policy
      -for <duration>                         default 90d; bounded like a grant
  token list <login>                        Tokens, live ones first
  token revoke <login> <token-id>           End one, keeping its history

  A token authenticates its owner but is never device-bound, so existing policy
  refuses it administrative actions and SSH certificates.

  A scope narrows further, and can never widen: policy still decides, and a
  token still cannot exceed its owner. It answers what Cedar cannot ask, because
  Cedar sees a principal and not the credential that presented it — was this
  token issued for this? Scopes cannot be changed, so a narrower token is a new
  one.

NOTIFICATION EMAIL
  mail settings                            How this deployment sends
  mail set [-host -port -from -tls ...]    Change it. Omitted fields are left
                                           alone; -password unchanged unless given
  mail test -to <address>                  Send one and print what the relay said
  mail status                              What is queued, and what is failing
  mail templates [-show <kind>] [-reset]   The wording, built-in or overridden

  Settings live in the database, not the configuration file, so a deployment
  running the published image can change them. Only mail.encryption_key is in
  the file, because it protects the relay password stored beside everything else.

  Nothing here authorises anything: these messages report what happened
  (ADR 0009). Recovery email is never a way in.

HOST ACCESS (SSH certificates)
  ssh [user@]<host> [-server <url>]        Log into a machine. Borrows a passkey
                                           ceremony from a browser, fetches a
                                           short-lived certificate, hands it to
                                           ssh-agent, and connects. Nothing is
                                           written to disk.
      -l <account>                           the local account, if not your own
      -print                                 print the certificate, do not connect
      -auth loopback|device                  which sign-in handoff; omitting it
                                             works out which can work here

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

TOKEN SIGNING KEY
  oidc key list                            Keys, and which one is signing
  oidc key rotate [-grace <dur>]           Sign with a new key; the previous
                                           one keeps verifying until every
                                           token it signed has expired

  This key signs ID tokens, access tokens and security events. The grace period
  defaults to the longest token lifetime any registered client is configured
  with, so the default is measured rather than assumed.

  join and whoami run on the host and never touch the database. Everything else
  here is administration and does.

AUTHORIZATION
  policy test <file.cedar> [-dsn <url>]    Compile a policy file. Offline
                                           without -dsn; with one, also reports
                                           groups and applications a rule names
                                           that do not exist. A rule naming a
                                           group that is not there never
                                           matches, and Cedar being default-deny
                                           makes that look like it working.
  policy publish <file> [-activate]        Store a new version
  policy activate <version>                Make a version live (rollback too)
  policy list                              Published versions
  policy show                              The live policy set

  decisions [<principal>] [-denied]        Why access was allowed or refused,
                                           newest first, naming the deciding
                                           rule. The question asked during an
                                           incident, so it does not need the
                                           console to be reachable.
      -limit <n>                             default 20

DIAGNOSIS
  policy rule list                         The live set, rule by rule, in words
  policy rule remove <id>                  Drop one and publish the result
  policy rule add <kind> <id> [flags]      Compose a rule without writing Cedar
      <kind> is web-access, application-access, ssh-login or run-as-root
      -group <name>                          who it applies to; omit for anyone
      -to <group> | -app <name>              which applications or hosts
      -anything                              every resource — deliberate, loud
      -account <a>,<b>                       SSH only; the default is their own
                                             login, and root is never one
      -stage                                 publish without activating

  A composed rule becomes text in the same document, published as an ordinary
  version and rolled back with policy activate. Comments and anything the
  builder does not recognise pass through untouched.

  The forbids and the administration tiers stay hand-written. They are the
  guardrails the other rules sit inside, so removing one goes through a policy
  file, where the change is reviewed as text.

  The binary carries the default set, so init needs no files on disk. Once
  published, policy lives in the database: a deployment running the image edits
  it the same way a source checkout does.

SECURITY EVENTS (SSF / CAEP)
  ssf stream add <app> -endpoint <url>      Push events to a receiver
      -events <a>,<b>                         default: all of them
  ssf stream list                           Configured receivers
  ssf stream pause|resume <app>             Stop or restart delivery, keeping
                                            the queue — resuming sends what
                                            was missed
  ssf stream remove <app>                   Forget a receiver entirely
  ssf status                                What is queued, and what is failing

  Revoking a session here ends it here. An application that issued its own
  session from an OIDC login learns nothing until its token expires, which for
  a compromised account is the whole incident. Tokens are signed with the OIDC
  signing key, so a receiver verifies them against the JWKS it already fetches.

PROVISIONING (SCIM 2.0)
  Base URL: <public-url>/scim/v2 — point Entra, Okta or anything else at it.

  cardinal grant provisioners <login>        Who may provision
  cardinal token create <login> -scope scim  The credential it authenticates with

  Both are needed: the token must carry the scim scope and policy must permit
  its owner to Provision. A system group is never provisionable, so an identity
  provider cannot make anybody a Cardinal administrator (ADR 0031).

AUDIT
  audit verify                             Verify the event log's hash chain

GLOBAL
  -dsn <url>    PostgreSQL connection string, for the commands that open it
                (or set CARDINAL_DSN; defaults to the local dev database)
  -server <url> Where Cardinal is, for the commands that sign in
                (or set CARDINAL_SERVER)
  -auth <flow>  loopback or device. Omitting it works out which can work here,
                which is right unless a multiplexer or a remote desktop makes
                the guess wrong

  Membership, creating an entity and taking one out of service — grant, revoke,
  members, memberships, history, <type> create, disable and enable — sign in
  and ask the API, as do ssh and host join. Policy governs them and the journal
  names who ran them. The rest still open the database, where it does not:
  passing -dsn to one that has moved prints that rather than a connection.

Grants should normally be bounded. Whoever asks for access almost always knows
when they will stop needing it, and a bounded grant cannot be forgotten.
`)
}
