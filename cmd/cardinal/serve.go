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

	"go.londer.be/cardinal/internal/auth"
	"go.londer.be/cardinal/internal/claims"
	"go.londer.be/cardinal/internal/config"
	"go.londer.be/cardinal/internal/httpapi"
	"go.londer.be/cardinal/internal/oidcprovider"
	"go.londer.be/cardinal/internal/policy"
	"go.londer.be/cardinal/internal/sshca"
	"go.londer.be/cardinal/internal/store"
	"go.londer.be/cardinal/internal/version"
	"go.londer.be/cardinal/internal/x509ca"
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

	// Refuse a database migrated by a newer Cardinal than this one.
	//
	// The downgrade case, and it used to be silent: an older binary started
	// happily against a newer schema and then failed one request at a time,
	// wherever a code path first touched a column it did not know about. The
	// symptom looked like a bug in whichever feature was unlucky rather than
	// like the wrong version running, which is the worst way to spend an
	// afternoon after a rollback.
	//
	// Checked before anything serves rather than during migration, because the
	// binary that must not run is precisely the one nobody is going to run
	// `migrate` with.
	ahead, err := st.SchemaAhead(ctx)
	if err != nil {
		return err
	}
	if len(ahead) > 0 {
		// Printed rather than returned as a single error string. The guidance
		// this trips (ST1005) is about error strings being fragments that
		// compose; this is an operator message with a list and a next step, and
		// squeezing it onto one punctuation-free line would make it useless at
		// the moment somebody most needs it.
		fmt.Fprintf(os.Stderr,
			"\n  This database has %d migration(s) this build does not contain:\n"+
				"    %s\n\n"+
				"  It was migrated by a newer Cardinal. This binary is %s.\n\n"+
				"  Either run the newer version again, or take the database back with\n"+
				"  `cardinal migrate -to <migration>` — from a backup taken before the\n"+
				"  upgrade, because a reversal restores the shape of the data and not\n"+
				"  the data itself.\n\n",
			len(ahead), strings.Join(ahead, "\n    "), version.String())
		return store.ErrSchemaAhead
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

	apiServer, err := httpapi.New(st, authSvc, cfg, httpapi.Options{
		DevMode: *dev,
		UI:      ui,
		Logger:  log,
		OIDC:    oidcProvider,
		SSHCA:   hostCA,
		X509CA:  certificateAuthority,
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
