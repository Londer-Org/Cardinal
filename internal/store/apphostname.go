package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/directory/event"
)

// The hostnames an application answers to.
//
// forwardAuth is asked about a hostname and nothing else — Traefik sends
// X-Forwarded-Host and there is no other handle on the thing being protected.
// This is what turns that into a directory entity, so "who may reach this
// application" can be group membership like everything else rather than a
// separate mechanism.
//
// Before this existed, the decision point classified every hostname identically
// and the shipped rule admitted every authenticated principal to every protected
// URL while reading as though it distinguished between them.

// ErrHostnameTaken means another application already answers to this name.
var ErrHostnameTaken = errors.New("store: another application already holds this hostname")

// AddApplicationHostname records a hostname an application answers to.
//
// Refused if any application already holds it. Two applications claiming one
// hostname is not a merge conflict to resolve at read time: whichever row won
// would decide which application's group membership governs the request, so the
// wrong one would silently authorize against the wrong rules.
func (s *Store) AddApplicationHostname(
	ctx context.Context, entityID uuid.UUID, hostname string, actorID *uuid.UUID,
) error {
	name, err := normalizeHostname(hostname)
	if err != nil {
		return err
	}

	return s.InTx(ctx, func(tx pgx.Tx) error {
		// The entity must exist and be an application. Checked rather than left
		// to the foreign key, which would accept a user or a host — and a host
		// answering forwardAuth for a hostname would put a machine's group
		// memberships in charge of who may reach a web application.
		var entityType string
		err := tx.QueryRow(ctx,
			`SELECT type FROM entities WHERE id = $1`, entityID).Scan(&entityType)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: entity %s", directory.ErrNotFound, entityID)
		}
		if err != nil {
			return fmt.Errorf("store: reading the entity: %w", err)
		}
		if directory.Type(entityType) != directory.TypeApplication {
			return fmt.Errorf("store: %s is a %s, and a hostname belongs to an application",
				entityID, entityType)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO application_hostnames (hostname, entity_id, added_by)
			VALUES ($1, $2, $3)`, name, entityID, actorID)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("%w: %s", ErrHostnameTaken, name)
			}
			return fmt.Errorf("store: adding application hostname: %w", err)
		}

		ev, err := event.New(event.ActionApplicationHostnameAdded, &entityID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// RemoveApplicationHostname withdraws one.
//
// Takes effect on the next request, unlike a certificate: forwardAuth asks at
// every request, so removing a hostname closes access immediately rather than
// at the next renewal.
func (s *Store) RemoveApplicationHostname(
	ctx context.Context, entityID uuid.UUID, hostname string, actorID *uuid.UUID,
) error {
	name, err := normalizeHostname(hostname)
	if err != nil {
		return err
	}

	return s.InTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM application_hostnames WHERE entity_id = $1 AND hostname = $2`,
			entityID, name)
		if err != nil {
			return fmt.Errorf("store: removing application hostname: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", directory.ErrNotFound, name)
		}

		ev, err := event.New(event.ActionApplicationHostnameRemoved, &entityID, actorID, nil)
		if err != nil {
			return err
		}
		return s.AppendEvent(ctx, tx, ev)
	})
}

// ApplicationHostname is one mapping, for a listing that spans applications.
type ApplicationHostname struct {
	Hostname        string
	ApplicationID   uuid.UUID
	ApplicationName string
}

// ApplicationEntry is an application as the console lists them.
//
// Every application entity, not every OIDC client. The two are not the same set
// and treating them as one made an entire category invisible: an application
// behind the proxy speaks no OIDC, has no client id, and appeared nowhere —
// while being exactly the kind of thing somebody needs to add a hostname to.
type ApplicationEntry struct {
	ID          uuid.UUID
	Name        string
	DisplayName string
	Disabled    bool
	Hostnames   []string
}

// ListApplications returns every application entity with the hostnames it
// answers to.
//
// Disabled ones are included and flagged. Retiring an application is a soft
// delete here as everywhere else, and a console that simply stopped showing it
// would leave somebody wondering where it went — and unable to enable it again.
func (s *Store) ListApplications(ctx context.Context) ([]ApplicationEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT e.id, e.name, coalesce(e.display_name, ''),
		       e.disabled_at IS NOT NULL,
		       coalesce(
		           array_agg(h.hostname ORDER BY h.hostname)
		               FILTER (WHERE h.hostname IS NOT NULL),
		           '{}') AS hostnames
		  FROM entities e
		  LEFT JOIN application_hostnames h ON h.entity_id = e.id
		 WHERE e.type = 'application'
		 GROUP BY e.id, e.name, e.display_name, e.disabled_at
		 ORDER BY e.name`)
	if err != nil {
		return nil, fmt.Errorf("store: listing applications: %w", err)
	}
	defer rows.Close()

	out := []ApplicationEntry{}
	for rows.Next() {
		var a ApplicationEntry
		if err := rows.Scan(&a.ID, &a.Name, &a.DisplayName,
			&a.Disabled, &a.Hostnames); err != nil {
			return nil, fmt.Errorf("store: scanning application: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetApplicationEnabled retires an application, or brings one back.
//
// By directory name, because an application behind the proxy has no client id
// and this has to reach both kinds. When it does have one, its tokens and
// standing consents go with it — the same thing DisableOIDCClient does, and for
// the same reason: an application that can no longer sign anyone in should not
// leave live tokens behind it.
//
// Enabling deliberately does not restore them. They were revoked, and a
// revocation that undoes itself is not one.
func (s *Store) SetApplicationEnabled(
	ctx context.Context, name string, enabled bool, actorID *uuid.UUID,
) error {
	app, err := s.LookupEntity(ctx, directory.TypeApplication, name)
	if err != nil {
		return err
	}

	if enabled {
		return s.EnableEntity(ctx, app.ID, actorID)
	}
	if err := s.DisableEntity(ctx, app.ID, actorID); err != nil {
		return err
	}

	// After the disable rather than inside it. If this fails the application is
	// already unable to obtain anything new, which is the property that matters
	// most; a retry cleans up the rest.
	if _, err := s.pool.Exec(ctx, `
		UPDATE oidc_tokens SET revoked_at = now()
		 WHERE client_id IN (SELECT client_id FROM oidc_clients WHERE entity_id = $1)
		   AND revoked_at IS NULL`, app.ID); err != nil {
		return fmt.Errorf("store: revoking tokens for a disabled application: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE oidc_consents SET revoked_at = now()
		 WHERE client_id IN (SELECT client_id FROM oidc_clients WHERE entity_id = $1)
		   AND revoked_at IS NULL`, app.ID); err != nil {
		return fmt.Errorf("store: revoking consents for a disabled application: %w", err)
	}
	return nil
}

// ApplicationForHostname resolves what forwardAuth was asked about.
//
// A disabled application resolves to nothing, so disabling one closes access to
// it through the proxy in the same breath as everywhere else — rather than
// leaving the hostname pointing at an entity whose group memberships still
// evaluate.
func (s *Store) ApplicationForHostname(
	ctx context.Context, hostname string,
) (*directory.Entity, error) {
	name, err := normalizeHostname(hostname)
	if err != nil {
		return nil, err
	}

	row := s.pool.QueryRow(ctx, `
		SELECT `+entityColumns+`
		  FROM entities
		 WHERE id = (SELECT entity_id FROM application_hostnames WHERE hostname = $1)
		   AND disabled_at IS NULL`, name)

	e, err := scanEntity(row)
	if errors.Is(err, directory.ErrNotFound) {
		return nil, fmt.Errorf("%w: no application answers to %q", directory.ErrNotFound, name)
	}
	return e, err
}

// normalizeHostname lowercases and strips a port.
//
// The port comes off because X-Forwarded-Host carries one when the proxy is not
// on 443, and `grafana.example.com:8443` and `grafana.example.com` are the same
// application. Lowercasing because DNS is case-insensitive and a browser may
// send either — the database constraint then refuses anything that reached it
// without passing through here.
//
// net.SplitHostPort rather than cutting at the first colon: `[::1]:8443` would
// otherwise normalise to `[`, and a literal address is what a lab or a
// single-machine deployment actually sends. It returns an error for a bare
// hostname and for a bare IPv6 address, which is why the result is only used
// when it succeeds.
func normalizeHostname(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if host, _, err := net.SplitHostPort(name); err == nil {
		name = host
	}
	name = strings.Trim(name, "[]")
	if name == "" {
		return "", errors.New("store: a hostname cannot be blank")
	}
	return name, nil
}
