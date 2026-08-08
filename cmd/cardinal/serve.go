package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"go.londer.be/cardinal/internal/ca/sshca"
	"go.londer.be/cardinal/internal/ca/x509ca"
	"go.londer.be/cardinal/internal/config"
	"go.londer.be/cardinal/internal/server/auth"
	"go.londer.be/cardinal/internal/server/claims"
	"go.londer.be/cardinal/internal/server/httpapi"
	"go.londer.be/cardinal/internal/server/mail"
	"go.londer.be/cardinal/internal/server/oidcprovider"
	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/store"
	"go.londer.be/cardinal/internal/version"
	"go.londer.be/cardinal/web"
)

func runServe(ctx context.Context, args []string) error {
	fs_ := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs_.String("config", "cardinal.toml", "path to the configuration file")
	dev := fs_.Bool("dev", false, "development mode: relaxes cookie security, do not use in production")
	if _, err := parse(fs_, args); err != nil {
		return errUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *dev {
		// Loud, because a production deployment started with -dev would serve
		// session cookies without the Secure flag, i.e. in cleartext over HTTP.
		log.Warn("DEVELOPMENT MODE — cookies are not marked Secure and the CSP is relaxed. " +
			"Never use this on a network anyone else can reach.")
	}

	st, err := store.Open(ctx, cfg.Database.DSN)
	if err != nil {
		return err
	}
	defer st.Close()

	// A schema newer than this binary is normal, and used to be fatal.
	//
	// Migrations only add — enforced by a test in migrations/ — so a build
	// running against a schema a version or two ahead simply does not use the
	// new columns. That is the property that makes rolling back a matter of
	// deploying the older image and nothing else, and refusing outright turned
	// every rollback into a schema operation performed under pressure.
	//
	// What still refuses is a migration whose author declared it incompatible.
	// The reason was written into the row when it was applied, so a binary that
	// predates the migration can read it even though it cannot read the file.
	drift, err := st.SchemaAhead(ctx)
	if err != nil {
		return err
	}
	if len(drift.Blocking) > 0 {
		fmt.Fprintf(os.Stderr,
			"\n  This database carries %d change(s) this build cannot run against:\n\n",
			len(drift.Blocking))
		for name, why := range drift.Blocking {
			fmt.Fprintf(os.Stderr, "    %s\n      %s\n", name, why)
		}
		fmt.Fprintf(os.Stderr,
			"\n  This binary is %s. Run the version that applied them.\n\n",
			version.String())
		return store.ErrSchemaBreaking
	}
	if len(drift.Unknown) > 0 {
		// Worth saying, not worth stopping for. Somebody looking at why a node
		// behaves differently from its neighbours should find this immediately.
		log.Warn("the database is newer than this build, which is supported",
			"migrations_ahead", len(drift.Unknown),
			"newest", drift.Unknown[len(drift.Unknown)-1],
			"version", version.String())
	}

	// And refuse a database that has not caught up with this binary.
	//
	// The other direction, and the one an upgrade walks into. Kubernetes made it
	// concrete: a Job's pod template is immutable, so `kubectl apply` with a new
	// image tag updates the Deployment and *rejects* the migration Job — the new
	// server rolls out and the migration never runs. Nothing noticed, because
	// "some migration has been applied" is true and was all anything checked.
	//
	// Enforced here rather than in the manifests because it then holds for every
	// deployment shape: a container, a Job, a systemd unit, somebody's laptop.
	behind, err := st.SchemaBehind(ctx)
	if err != nil {
		return err
	}
	if len(behind) > 0 {
		fmt.Fprintf(os.Stderr,
			"\n  This database is missing %d migration(s) this build needs:\n"+
				"    %s\n\n"+
				"  Apply them first:\n\n"+
				"      cardinal migrate\n\n"+
				"  Migrations are a separate step on purpose — applying one while other\n"+
				"  replicas still serve the old schema is how rolling deploys break — so\n"+
				"  this will not do it for you.\n\n",
			len(behind), strings.Join(behind, "\n    "))
		return store.ErrSchemaBehind
	}

	idle, absolute := cfg.Sessions.Effective()
	st.SetSessionLimits(store.SessionLimits{Idle: idle, Absolute: absolute})
	// Strings, not durations: slog renders a time.Duration as nanoseconds, and
	// "28800000000000" is a number nobody reads as eight hours.
	log.Info("session limits", "idle", idle.String(), "absolute", absolute.String())

	authSvc, err := auth.NewService(st, cfg)
	if err != nil {
		return err
	}

	ui, err := web.Assets()
	if err != nil {
		// Serving the API without a UI is legitimate — it is what a headless
		// deployment or a frontend rebuild looks like — so this is a warning,
		// not a failure.
		log.Warn("no embedded admin UI; serving API only", "reason", err)
		ui = nil
	}

	var oidcProvider *oidcprovider.Provider
	if cfg.OIDC.Enabled {
		oidcProvider, err = oidcprovider.New(ctx, st, claims.NewResolver(st), cfg)
		if err != nil {
			return err
		}
		log.Info("OpenID Connect provider enabled", "issuer", cfg.Server.PublicURL)
	}

	var hostCA *sshca.CA
	if cfg.SSH.Enabled {
		hostCA = sshca.New(st, cfg.SSH.CAEncryptionKey)
		// Deliberately does not check that a key exists or is signing. A
		// deployment enabling host access before publishing its authority is
		// in a normal intermediate state, and refusing to start would make the
		// safe order — publish, distribute, then activate — the one that
		// prevents the server from running.
		log.Info("host access enabled — SSH certificates may be issued")
	}

	var certificateAuthority *x509ca.CA
	if cfg.X509.Enabled {
		certificateAuthority, err = x509ca.New(st, cfg.X509.CAEncryptionKey)
		if err != nil {
			return err
		}
		// Same reasoning as the SSH authority above: no check that a key exists
		// or is active, because publishing a root and distributing it before
		// activating is the safe order and refusing to start would punish it.
		log.Info("ACME enabled — X.509 certificates may be issued",
			"directory", strings.TrimRight(cfg.Server.PublicURL, "/")+"/acme/directory")
	}

	// Notifications, if a relay has been configured. The settings live in the
	// database rather than here, so this is built unconditionally and does
	// nothing until somebody turns it on — which means enabling mail does not
	// need a restart.
	notifier := mail.NewNotifier(st, cfg.Server.PublicURL, cfg.WebAuthn.RPDisplayName, log)

	apiServer, err := httpapi.New(st, authSvc, cfg, httpapi.Options{
		DevMode:  *dev,
		UI:       ui,
		Logger:   log,
		OIDC:     oidcProvider,
		SSHCA:    hostCA,
		Notifier: notifier,
		X509CA:   certificateAuthority,
	})
	if err != nil {
		return err
	}

	// Load the active policy before serving. A server with no policy denies
	// everything, which is safe but is still an outage, so it is worth being
	// loud about at startup rather than discovering it from the first 503.
	if version, err := st.ActivePolicy(ctx); err != nil {
		log.Error("no active policy — all authorization will be denied; "+
			"publish one with `cardinal policy publish`", "error", err)
	} else {
		engine, err := policy.NewEngine([]byte(version.Document), version.Version)
		if err != nil {
			// A stored policy that no longer compiles means the engine changed
			// under a version that was valid when published. Refusing to start
			// is better than serving with no rules.
			return fmt.Errorf("loading active policy version %d: %w", version.Version, err)
		}
		apiServer.ReloadPolicy(engine)
	}

	srv := &http.Server{
		Addr:    cfg.Server.Listen,
		Handler: apiServer.Handler(),
		// Bounded so a slow or stalled client cannot occupy a connection
		// indefinitely. WriteTimeout is generous enough for a WebAuthn ceremony
		// that waits on a hardware key.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	go backgroundMaintenance(ctx, st, log)
	go deliverMail(ctx, notifier, cfg.Mail.EncryptionKey, log)
	go watchPolicy(ctx, st, apiServer, log)

	errCh := make(chan error, 1)
	go func() {
		log.Info("cardinal listening",
			"addr", cfg.Server.Listen,
			"rp_id", cfg.WebAuthn.RPID,
			"ui", ui != nil)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
		log.Info("shutting down")
		// Give in-flight requests a chance to finish rather than severing
		// someone's authentication mid-ceremony.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// backgroundMaintenance clears expired ephemeral rows.
//
// Nothing here is security-critical: expiry is enforced by every query that
// reads these tables, so a maintenance run that never happens costs disk space
// rather than correctness.
func backgroundMaintenance(ctx context.Context, st *store.Store, log *slog.Logger) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := st.PurgeExpiredCeremonies(ctx); err != nil {
				log.WarnContext(ctx, "purging ceremonies failed", "error", err)
			} else if n > 0 {
				log.DebugContext(ctx, "purged ceremonies", "count", n)
			}
			if _, err := st.PurgeRateLimits(ctx, time.Hour); err != nil {
				log.WarnContext(ctx, "purging rate limits failed", "error", err)
			}
		}
	}
}

// policyReloadInterval is how stale a policy change may be on a node that did
// not serve the activation.
//
// Ten seconds. Short enough that a rollback during an incident takes effect
// while somebody is still looking at the screen, long enough that the query —
// one integer, on an index — is nothing.
//
// PostgreSQL 19's targeted LISTEN/NOTIFY would make this near-instant and is
// the obvious next step, but it would not replace this loop: a notification is
// a hint that can be missed, never a guarantee (ADR 0004), so the table stays
// the source of truth and a node still has to reconcile on its own. Polling
// first means the correctness argument does not depend on delivery.
const policyReloadInterval = 10 * time.Second

// watchPolicy keeps the live engine in step with what is activated.
//
// Without this, `cardinal policy activate` and the console's rollback button
// both changed a row and nothing else: the running server kept evaluating the
// set it loaded at startup until somebody restarted it. The CLI said so — "
// activated — restart the server, or it keeps serving the previous set" — which
// made it a documented limitation rather than a surprise, but it also made
// rolling back a bad policy a two-step operation whose second step needs a
// shell on the server.
//
// That is the wrong shape for the one action most likely to be taken in a
// hurry. A rollback button that changed a row and left the old rules enforced
// would be worse than no button, because it reports success.
func watchPolicy(ctx context.Context, st *store.Store, server *httpapi.Server, log *slog.Logger) {
	ticker := time.NewTicker(policyReloadInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			version, err := st.ActivePolicyVersion(ctx)
			if err != nil {
				if !errors.Is(err, store.ErrNoActivePolicy) {
					log.WarnContext(ctx, "checking the active policy failed", "error", err)
				}
				continue
			}
			if server.PolicyVersion() == version {
				continue
			}

			active, err := st.ActivePolicy(ctx)
			if err != nil {
				log.WarnContext(ctx, "reading the active policy failed", "error", err)
				continue
			}
			engine, err := policy.NewEngine([]byte(active.Document), active.Version)
			if err != nil {
				// Keep serving the set we have. A version that does not compile
				// cannot be enforced, and swapping in nothing would deny
				// everything — turning a bad publish into a total outage.
				log.ErrorContext(ctx, "the activated policy does not compile — "+
					"continuing with the previous set",
					"version", active.Version, "error", err)
				continue
			}
			server.ReloadPolicy(engine)
		}
	}
}

// deliverMail sends whatever the outbox holds.
//
// Its own loop rather than part of backgroundMaintenance, which runs every ten
// minutes: a notification that somebody's passkey changed is worth very little
// ten minutes later, and the whole point of these messages is that the person
// finds out in time to do something.
//
// Failures are the queue's problem, not this loop's. A row that will not send
// has already had its next attempt moved forward, so a broken relay slows
// nothing down and an unreachable one costs one connection attempt a minute.
func deliverMail(ctx context.Context, notifier *mail.Notifier, sealKey string, log *slog.Logger) {
	const (
		interval = 15 * time.Second
		batch    = 20
	)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sent, err := notifier.Deliver(ctx, sealKey, batch)
			if err != nil {
				// Not fatal, and not per-message: this is the settings being
				// unreadable or the seal key being wrong, which is worth saying
				// once a cycle rather than staying silent.
				log.WarnContext(ctx, "could not deliver notifications", "error", err)
				continue
			}
			if sent > 0 {
				log.InfoContext(ctx, "notifications sent", "count", sent)
			}
		}
	}
}
