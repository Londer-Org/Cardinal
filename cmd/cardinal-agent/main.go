// Command cardinal-agent runs on a managed host.
//
// It is a separate binary from `cardinal` because the two have opposite
// requirements. The CLI talks to the database and is run by an administrator on
// a workstation; the agent talks only to Cardinal's HTTP API, runs unattended as
// root on every machine in the fleet, and must keep working when Cardinal does
// not. Shipping the database driver and the migration files onto a thousand
// hosts to get a varlink socket would be the wrong trade.
//
// Deliberately not a container. It serves a socket nss-systemd must reach,
// writes /etc/sudoers.d, manages sshd trust configuration, and must survive a
// reboot before any container runtime starts — all the operational cost of
// containerising, none of the isolation.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/agent"
	"github.com/arthur-lonfils/cardinal/internal/hostclient"
	"github.com/arthur-lonfils/cardinal/internal/shadow"
	"github.com/arthur-lonfils/cardinal/internal/sudoers"
	"github.com/arthur-lonfils/cardinal/internal/userdb"
)

var errUsage = errors.New("usage")

func main() { os.Exit(main1()) }

// main1 exists so the deferred teardown actually runs: os.Exit skips defers, so
// a signal handler released with `defer` in main would never be released at all.
func main1() int {
	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := run(ctx, os.Args[1:])
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		usage()
		return 2
	default:
		fmt.Fprintf(os.Stderr, "cardinal-agent: %v\n", err)
		return 1
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "enroll":
		return runEnroll(ctx, args[1:])
	case "run":
		return runAgent(ctx, args[1:])
	case "status":
		return runStatus(args[1:])
	case "sudoers":
		return runSudoers(ctx, args[1:])
	case "hostcert":
		return runHostCert(args[1:])
	case "shadow":
		return runShadow(ctx, args[1:])
	case "doctor":
		return runDoctor(ctx, args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return errUsage
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cardinal-agent — Cardinal on a managed host

USAGE
  cardinal-agent <command> [flags]

  enroll -server <url> -token <token>   Register this machine's key. Once, at
                                        the console, with a token from
                                        `+"`cardinal host enroll`"+`.
  run -server <url>                     Fetch this host's assignment and serve
                                        POSIX identity to nss-systemd.
  status                                What is cached, and how old it is.
  sudoers                               Print the drop-in that would be
                                        installed, without installing it.
  hostcert                              Show the installed host certificate.
  shadow -server <url>                  Report what cutting over would change.
                                        Enforces nothing: no socket, no sudoers
                                        file, no certificate.
  doctor                                Check this machine's prerequisites and
                                        say what is missing. Changes nothing.

FLAGS
  -key <path>        this host's private key (default `+hostclient.DefaultKeyPath+`)
  -cache <path>      cached assignment (default `+agent.DefaultCachePath+`)
  -interval <dur>    how often to refresh (default 5m)
  -socket-dir <path> where nss-systemd looks (default `+userdb.DefaultRunDir+`)
  -sudoers <path>    drop-in to render (default `+sudoers.DefaultPath+`;
                     empty disables sudoers rendering entirely)
  -host-key <path>   this machine's SSH host key (default
                     `+agent.DefaultHostKeyPath+`; empty disables
                     host certificate renewal)
  -host-cert <path>  where to install the signed certificate
  -sshd-config <p>   sshd drop-in pointing at it

The cache is what answers lookups; the network is only how it is updated. A host
that cannot reach Cardinal keeps resolving the people it last knew about, which
is why a Cardinal outage is not a fleet outage.
`)
}

func runEnroll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := fs.String("server", "", "base URL of the Cardinal server")
	token := fs.String("token", "", "enrollment token from `cardinal host enroll`")
	keyPath := fs.String("key", hostclient.DefaultKeyPath, "where to write this host's key")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *server == "" || *token == "" {
		return errUsage
	}

	signer, err := hostclient.GenerateKey(*keyPath)
	if err != nil {
		return err
	}

	name, err := hostclient.Enroll(ctx, nil, *server, *token, signer.PublicKey())
	if err != nil {
		// Never registered, so the key is useless — and leaving it behind would
		// make the next attempt fail on O_EXCL, complaining about a key this
		// host does not really have.
		_ = os.Remove(*keyPath)
		return err
	}

	fmt.Printf("enrolled as %s\n", name)
	fmt.Printf("  key %s\n", *keyPath)
	return nil
}

func runAgent(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "",
		"configuration file; every flag below overrides what it sets")
	server := fs.String("server", "", "base URL of the Cardinal server")
	keyPath := fs.String("key", hostclient.DefaultKeyPath, "this host's key")
	cachePath := fs.String("cache", agent.DefaultCachePath, "cached assignment")
	interval := fs.Duration("interval", agent.DefaultInterval, "how often to refresh")
	socketDir := fs.String("socket-dir", userdb.DefaultRunDir, "where nss-systemd looks")
	sudoersPath := fs.String("sudoers", sudoers.DefaultPath,
		"drop-in to render; empty disables sudoers rendering")
	hostKeyPath := fs.String("host-key", agent.DefaultHostKeyPath,
		"this machine's SSH host key; empty disables host certificate renewal")
	hostCertPath := fs.String("host-cert", agent.DefaultHostCertPath,
		"where to install the signed host certificate")
	sshdDropIn := fs.String("sshd-config", agent.DefaultSSHDDropIn,
		"sshd drop-in pointing at the certificate; empty disables writing it")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	// A file, then flags on top. The systemd unit names only the file, so an
	// operator changing a setting edits configuration rather than a unit — which
	// would otherwise conflict on every package upgrade.
	if *configPath != "" {
		cfg, err := agent.LoadConfig(*configPath)
		if err != nil {
			return err
		}
		applyConfig(fs, cfg, server, keyPath, cachePath, interval, socketDir,
			sudoersPath, hostKeyPath, hostCertPath, sshdDropIn)
	}

	if *server == "" {
		return errUsage
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	signer, err := hostclient.LoadKey(*keyPath)
	if err != nil {
		return fmt.Errorf("%w\n\n  Enrol first: cardinal-agent enroll -server %s -token <token>",
			err, *server)
	}

	a := &agent.Agent{
		Identity:    &hostclient.Identity{Server: *server, Signer: signer},
		CachePath:   *cachePath,
		Interval:    *interval,
		SudoersPath: *sudoersPath,
		Log:         log,

		HostKeyPath:    *hostKeyPath,
		HostCertPath:   *hostCertPath,
		SSHDDropInPath: *sshdDropIn,
	}

	// Checked once at startup, and reported rather than repaired. A drop-in
	// that nothing includes is silently inert — the agent would report success
	// while granting nobody anything — but editing /etc/sudoers to fix it would
	// break the rule that makes this safe: Cardinal only ever adds, and can
	// never take away an account's existing access.
	if *sudoersPath != "" {
		if ok, err := sudoers.IncludeDirConfigured("/etc/sudoers", filepath.Dir(*sudoersPath)); err != nil {
			log.Warn("could not check whether sudo reads the drop-in directory", "error", err)
		} else if !ok {
			log.Warn("sudo does not read this directory, so the rendered rules will do nothing",
				"directory", filepath.Dir(*sudoersPath),
				"fix", "add '@includedir "+filepath.Dir(*sudoersPath)+"' to /etc/sudoers with visudo")
		}
	}

	// Before the socket exists, so the first lookup is answered from the cache
	// rather than racing the first fetch. A machine rebooting during a Cardinal
	// outage depends entirely on this line.
	switch cached, err := a.LoadCache(); {
	case err == nil:
		log.Info("loaded cached assignment",
			"host", cached.Host, "users", len(cached.Users),
			"age", cached.Age().Round(time.Second))
	case agent.CacheMissing(err):
		log.Info("no cached assignment yet; nothing will resolve until the first refresh")
	default:
		// A cache that exists and will not parse is a different problem, and
		// silently continuing would leave a machine serving nothing while the
		// file sat there looking fine.
		return err
	}

	listener, err := listen(ctx, *socketDir)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()

	provider := &userdb.Server{
		ServiceName: userdb.ServiceName,
		Source:      a.Source,
		Log:         log,
	}

	errs := make(chan error, 2)
	go func() { errs <- provider.Serve(ctx, listener) }()
	go func() { errs <- a.Run(ctx) }()

	log.Info("serving POSIX identity",
		"socket", userdb.SocketPath(*socketDir, userdb.ServiceName),
		"server", *server, "interval", interval.String())

	if err := <-errs; err != nil {
		return err
	}
	return nil
}

// listen creates the socket nss-systemd will find.
//
// The basename is the service name, which is the entire discovery mechanism —
// nss-systemd scans the directory and asks each socket it finds, passing the
// filename back as the `service` field for the provider to verify.
func listen(ctx context.Context, dir string) (net.Listener, error) {
	// 0755, because every process that resolves a name has to traverse this —
	// `ls -l` run by anybody, not only root. It is where systemd itself keeps
	// userdb sockets and it has the same mode there.
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // see above
		return nil, fmt.Errorf("cardinal-agent: creating %s: %w", dir, err)
	}

	path := userdb.SocketPath(dir, userdb.ServiceName)

	// sun_path is 108 bytes on Linux, and exceeding it fails at bind(2) with
	// "invalid argument" — which says nothing about the length and sends
	// whoever hit it looking at permissions. The default path is nowhere near
	// the limit; a -socket-dir under a deep temporary directory is, which is
	// how this was found.
	if len(path) >= 108 {
		return nil, fmt.Errorf(
			"cardinal-agent: the socket path is %d bytes and the kernel allows 107 "+
				"(%s) — use a shorter -socket-dir", len(path), path)
	}

	// A stale socket from a killed agent would make Listen fail with "address
	// already in use" on a file nothing is listening to. Removing it is safe
	// because two agents on one host is already a misconfiguration.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("cardinal-agent: removing stale socket: %w", err)
	}

	var config net.ListenConfig
	listener, err := config.Listen(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("cardinal-agent: listening on %s: %w", path, err)
	}

	// World-connectable, because every process that resolves a name has to
	// reach it — `ls -l` run by anybody, not only root. The socket answers
	// exactly what `getent passwd` would, so there is nothing here to protect
	// that is not already public on a Unix machine.
	if err := os.Chmod(path, 0o666); err != nil { //nolint:gosec // world-connectable on purpose; see above
		_ = listener.Close()
		return nil, fmt.Errorf("cardinal-agent: setting socket permissions: %w", err)
	}

	return listener, nil
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cachePath := fs.String("cache", agent.DefaultCachePath, "cached assignment")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	cached, err := agent.Load(*cachePath)
	if err != nil {
		if agent.CacheMissing(err) {
			return errors.New("this host has no cached assignment — it has never " +
				"refreshed, so nothing will resolve")
		}
		return err
	}

	fmt.Printf("%s\n\n", cached.Host)
	fmt.Printf("  fetched  %s ago\n", cached.Age().Round(time.Second))
	fmt.Printf("  users    %d\n", len(cached.Users))
	fmt.Printf("  groups   %d\n", len(cached.Groups))

	if len(cached.Unnumbered) > 0 {
		fmt.Printf("\n  %d user(s) may log in here and have no uid:\n", len(cached.Unnumbered))
		for _, name := range cached.Unnumbered {
			fmt.Printf("    %s\n", name)
		}
		fmt.Println("\n  They will be issued certificates and then refused by sshd,")
		fmt.Println("  which says nothing about why. Run `cardinal posix assign user <name>`.")
	}
	return nil
}

// runSudoers prints what would be installed.
//
// Because the alternative way to find out is to install it, and this is the one
// file on the machine where being wrong stops sudo working for everybody
// including root.
func runSudoers(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("sudoers", flag.ContinueOnError)
	cachePath := fs.String("cache", agent.DefaultCachePath, "cached assignment")
	check := fs.Bool("check", false, "also run visudo against the rendered file")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	cached, err := agent.Load(*cachePath)
	if err != nil {
		if agent.CacheMissing(err) {
			return errors.New("this host has no cached assignment — nothing to render")
		}
		return err
	}

	content, err := sudoers.Render(cached.Sudoers(), cached.Host, cached.FetchedAt)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(content); err != nil {
		return err
	}

	if !*check {
		return nil
	}

	tmp, err := os.CreateTemp("", "cardinal-sudoers-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o440); err != nil { //nolint:gosec // the mode sudo requires
		return err
	}
	if err := sudoers.Validate(ctx, tmp.Name()); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "\n  visudo accepts this file.")
	return nil
}

// runHostCert shows what this machine currently proves about itself.
//
// The question it answers is "why is ssh still asking me to accept a
// fingerprint", and the answers are usually one of three: no certificate, a
// certificate for names nobody types, or sshd not being told to present it.
func runHostCert(args []string) error {
	fs := flag.NewFlagSet("hostcert", flag.ContinueOnError)
	certPath := fs.String("host-cert", agent.DefaultHostCertPath, "installed certificate")
	dropIn := fs.String("sshd-config", agent.DefaultSSHDDropIn, "sshd drop-in")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	cert, err := agent.ReadHostCertificate(*certPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no host certificate at %s — this machine still relies "+
				"on users accepting its fingerprint", *certPath)
		}
		return err
	}

	fmt.Printf("%s\n\n", *certPath)
	fmt.Printf("  serial      %d\n", cert.Serial)
	fmt.Printf("  principals  %s\n", strings.Join(cert.Principals, ", "))
	fmt.Printf("  expires     %s (in %s)\n",
		cert.ValidUntil.Local().Format(time.RFC3339),
		time.Until(cert.ValidUntil).Round(time.Minute))

	// Having a certificate and not presenting it is the failure that looks like
	// success, so it is checked rather than assumed.
	if _, err := os.Stat(*dropIn); err != nil {
		fmt.Fprintf(os.Stderr,
			"\n  WARNING: %s does not exist, so sshd is probably not presenting\n"+
				"  this certificate and clients still see a bare host key.\n", *dropIn)
	}

	fmt.Fprintln(os.Stderr,
		"\n  For clients, in known_hosts — one line, for the whole fleet:\n"+
			"    @cert-authority <pattern> $(cardinal ssh ca trust)")
	return nil
}

// runShadow reports what would change, and changes nothing.
//
// The command an operator runs on every machine before deciding to cut any of
// them over. It builds an Agent that installs nothing — every path left empty
// on purpose, so the "changes nothing" claim is a property of the object rather
// than of remembering not to call something.
func runShadow(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("shadow", flag.ContinueOnError)
	server := fs.String("server", "", "base URL of the Cardinal server")
	keyPath := fs.String("key", hostclient.DefaultKeyPath, "this host's key")
	asJSON := fs.Bool("json", false, "emit the report as JSON, for collecting across a fleet")
	extra := fs.String("users", "",
		"comma-separated names to check that Cardinal does not know about")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *server == "" {
		return errUsage
	}

	signer, err := hostclient.LoadKey(*keyPath)
	if err != nil {
		return err
	}

	// Deliberately not given a cache path, a sudoers path, a host key or a
	// socket directory. An Agent with none of those cannot write anything, so
	// shadow mode is read-only by construction rather than by discipline.
	a := &agent.Agent{
		Identity: &hostclient.Identity{Server: *server, Signer: signer},
	}

	// Fetch, not Refresh. Refresh writes the cache, renders sudoers and renews
	// the certificate — everything shadow mode exists not to do.
	assignment, err := a.Fetch(ctx)
	if err != nil {
		return err
	}

	expected := make([]shadow.Expected, 0, len(assignment.Users))
	byGID := map[int]string{}
	for _, g := range assignment.Groups {
		byGID[g.GID] = g.Name
	}
	for _, u := range assignment.Users {
		want := shadow.Expected{
			Name: u.Name, UID: u.UID, GID: u.GID,
			Home: u.Home, Shell: u.Shell, Sudo: u.Sudo,
		}
		for _, gid := range u.Groups {
			if name, ok := byGID[gid]; ok {
				want.Groups = append(want.Groups, name)
			}
		}
		expected = append(expected, want)
	}

	// Names Cardinal has never heard of, which is the one thing this cannot
	// discover on its own: directory-backed NSS providers disable enumeration by
	// default, so there is usually no asking the machine who else it knows
	// about. Passed separately from the
	// assignment because the question is different — "does Cardinal know this
	// person at all", not "do the two agree about them".
	var alsoCheck []string
	for _, name := range strings.Split(*extra, ",") {
		if name = strings.TrimSpace(name); name != "" {
			alsoCheck = append(alsoCheck, name)
		}
	}

	report, err := shadow.Compare(ctx, assignment.Host, expected, alsoCheck, shadow.Local{})
	if err != nil {
		return err
	}

	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}

	printReport(report)

	// Non-zero when cutting over would destroy something, so this can be the
	// gate in whatever runs it across a fleet.
	if len(report.Blocking()) > 0 {
		return errBlocking
	}
	return nil
}

// errBlocking is not a failure of the command — the comparison worked. It is
// the answer being "no".
var errBlocking = errors.New("cutting this host over would change uid or gid ownership")

func printReport(report *shadow.Report) {
	fmt.Printf("%s\n\n", report.Host)

	// Writes to a tabwriter cannot fail in a way worth handling — it buffers into
	// memory, and Flush is where a real error would surface.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "USER\tWHAT\tNOW\tCARDINAL\tVERDICT")
	for _, f := range report.Findings {
		if f.Severity == shadow.Match {
			continue
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			f.User, f.What, f.Local, f.Cardinal, f.Severity)
	}
	_ = w.Flush()

	counts := report.Counts()
	fmt.Printf("\n  %d matching, %d additive, %d to review, %d blocking\n",
		counts[shadow.Match], counts[shadow.Additive],
		counts[shadow.Review], counts[shadow.Blocking])

	for _, f := range report.Blocking() {
		fmt.Fprintf(os.Stderr, "\n  BLOCKING  %s %s: %s → %s\n    %s\n",
			f.User, f.What, f.Local, f.Cardinal, f.Why)
	}

	if len(report.Blocking()) > 0 {
		fmt.Fprintln(os.Stderr,
			"\n  Do not cut this host over. Align the numbers first — either import\n"+
				"  the existing ones into Cardinal, or move the files. There is no\n"+
				"  third option: the filesystem recorded a number, not a name.")
	}

	// Names that were asked about and turned up nowhere. Printed rather than
	// dropped, because "I checked and there is no such account" and "I forgot to
	// check" look identical in a report that omits them.
	if len(report.Unchecked) > 0 {
		fmt.Printf("\n  Neither system knows: %s\n", strings.Join(report.Unchecked, ", "))
	}

	fmt.Fprintln(os.Stderr,
		"\n  Note: accounts this machine can already resolve and Cardinal has never\n"+
			"  heard of are invisible here — enumeration is usually off on both\n"+
			"  sides. Name them with -users.")
}

// applyConfig fills in every setting the command line did not.
//
// Explicitly, by asking the FlagSet which flags were actually given, rather than
// comparing against defaults — a flag set to the same value as its default is
// still an operator saying something, and treating it as unset would silently
// ignore them.
func applyConfig(fs *flag.FlagSet, cfg *agent.Config,
	server, keyPath, cachePath *string, interval *time.Duration,
	socketDir, sudoersPath, hostKeyPath, hostCertPath, sshdDropIn *string,
) {
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	set := func(name string, target *string, value string) {
		if !given[name] {
			*target = value
		}
	}

	set("server", server, cfg.Server)
	set("key", keyPath, cfg.KeyPath)
	set("cache", cachePath, cfg.CachePath)
	set("socket-dir", socketDir, cfg.SocketDir)
	set("sudoers", sudoersPath, cfg.SudoersPath)
	set("host-key", hostKeyPath, cfg.HostKeyPath)
	set("host-cert", hostCertPath, cfg.HostCertPath)
	set("sshd-config", sshdDropIn, cfg.SSHDConfigPath)

	if !given["interval"] {
		*interval = time.Duration(cfg.Interval)
	}
}

// runDoctor reports what this machine still needs.
//
// The package installs a binary, a unit and a config file and stops — it does
// not reorder nsswitch.conf or edit /etc/sudoers, because a security product
// that rearranges how a machine resolves usernames as a side effect of an
// install is the surprise that loses people's trust. This is the other half of
// that decision: say precisely what is missing, and how to fix it.
func runDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := fs.String("config", agent.DefaultConfigPath, "configuration file")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		return err
	}

	checks := agent.Diagnose(ctx, cfg)

	fmt.Printf("cardinal-agent, against %s\n\n", cfg.Server)
	for _, c := range checks {
		fmt.Println(c.Describe())
	}

	outstanding := 0
	for _, c := range checks {
		if c.OK {
			continue
		}
		outstanding++
		fmt.Printf("\n  %s:\n    %s\n", c.Name, c.Advice)
	}

	fmt.Println()
	if outstanding == 0 {
		fmt.Println("  Ready.")
		return nil
	}

	if !agent.Ready(checks) {
		// Non-zero only when something fatal is outstanding, so this can gate a
		// rollout without failing on a machine that simply has no sshd.
		return fmt.Errorf("%w: %d thing(s) to fix", agent.ErrNotReady, outstanding)
	}
	fmt.Printf("  %d thing(s) to fix, none of which stop the agent working.\n", outstanding)
	return nil
}
