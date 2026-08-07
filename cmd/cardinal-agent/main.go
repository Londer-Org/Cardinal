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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/agent"
	"github.com/arthur-lonfils/cardinal/internal/hostclient"
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

FLAGS
  -key <path>        this host's private key (default `+hostclient.DefaultKeyPath+`)
  -cache <path>      cached assignment (default `+agent.DefaultCachePath+`)
  -interval <dur>    how often to refresh (default 5m)
  -socket-dir <path> where nss-systemd looks (default `+userdb.DefaultRunDir+`)

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
	server := fs.String("server", "", "base URL of the Cardinal server")
	keyPath := fs.String("key", hostclient.DefaultKeyPath, "this host's key")
	cachePath := fs.String("cache", agent.DefaultCachePath, "cached assignment")
	interval := fs.Duration("interval", agent.DefaultInterval, "how often to refresh")
	socketDir := fs.String("socket-dir", userdb.DefaultRunDir, "where nss-systemd looks")
	if err := fs.Parse(args); err != nil {
		return errUsage
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
		Identity:  &hostclient.Identity{Server: *server, Signer: signer},
		CachePath: *cachePath,
		Interval:  *interval,
		Log:       log,
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
