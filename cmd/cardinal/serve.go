package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/auth"
	"github.com/arthur-lonfils/cardinal/internal/claims"
	"github.com/arthur-lonfils/cardinal/internal/config"
	"github.com/arthur-lonfils/cardinal/internal/httpapi"
	"github.com/arthur-lonfils/cardinal/internal/oidcprovider"
	"github.com/arthur-lonfils/cardinal/internal/policy"
	"github.com/arthur-lonfils/cardinal/internal/store"
	"github.com/arthur-lonfils/cardinal/web"
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

	apiServer, err := httpapi.New(st, authSvc, cfg, httpapi.Options{
		DevMode: *dev,
		UI:      ui,
		Logger:  log,
		OIDC:    oidcProvider,
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
