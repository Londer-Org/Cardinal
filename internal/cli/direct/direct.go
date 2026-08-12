// Package direct opens the database.
//
// The path that reaches PostgreSQL without authenticating anybody, shared by
// `cardinal-server` — which needs it to migrate and to perform first-run setup
// — and by the handful of `cardinal` commands that exist to recover from
// Cardinal refusing you (ADR 0033).
//
// Nothing here is governed by policy, because there is no principal on this
// path to govern. Whoever holds the connection string can do anything the
// database allows, and that is not something Cardinal can change: psql exists.
// What this package is for is keeping the list of things that take that route
// short, and in one place where it can be read.
package direct

import (
	"context"
	"os"

	"go.londer.be/cardinal/internal/config"
	"go.londer.be/cardinal/internal/store"
)

// defaultDSN is the local development database, whose password is in the
// Makefile and the README already.
const defaultDSN = "postgres://cardinal:cardinal@localhost:5433/cardinal?sslmode=disable" //nolint:gosec // as above

// Open connects, resolving the connection string the usual way.
func Open(ctx context.Context, dsnFlag string) (*store.Store, error) {
	return store.Open(ctx, DSN(dsnFlag))
}

// DSN resolves where the database is: the flag, then the environment, then a
// configuration file, then the development default.
func DSN(flagValue string) string {
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

// ConfigSearchPaths are tried in order. The container path comes first because
// that is where a deployment mounts it, and a stray cardinal.toml in the
// working directory should not silently win over the mounted one.
var ConfigSearchPaths = []string{
	"/etc/cardinal/cardinal.toml",
	"cardinal.toml",
}

func dsnFromConfig() string {
	for _, path := range ConfigSearchPaths {
		cfg, err := config.Load(path)
		if err == nil && cfg.Database.DSN != "" {
			return cfg.Database.DSN
		}
	}
	return ""
}

// LoadConfig reads a configuration file, or finds one on the usual paths.
//
// Used where a command needs a setting rather than a database: the relying
// party check, the seal keys, and the effective-configuration listing.
func LoadConfig(path string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	var lastErr error
	for _, candidate := range ConfigSearchPaths {
		cfg, err := config.Load(candidate)
		if err == nil {
			return cfg, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
