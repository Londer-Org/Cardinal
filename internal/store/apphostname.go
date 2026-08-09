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

// ListApplicationHostnames returns the hostnames an application answers to.
func (s *Store) ListApplicationHostnames(
	ctx context.Context, entityID uuid.UUID,
) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT hostname FROM application_hostnames
		  WHERE entity_id = $1 ORDER BY hostname`, entityID)
	if err != nil {
		return nil, fmt.Errorf("store: listing application hostnames: %w", err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: scanning application hostname: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// ApplicationHostname is one mapping, for a listing that spans applications.
type ApplicationHostname struct {
	Hostname        string
	ApplicationID   uuid.UUID
	ApplicationName string
}

// AllApplicationHostnames returns every mapping, for `cardinal app hostname
// list` with no application named and for the console.
func (s *Store) AllApplicationHostnames(ctx context.Context) ([]ApplicationHostname, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT h.hostname, h.entity_id, e.name
		  FROM application_hostnames h
		  JOIN entities e ON e.id = h.entity_id
		 ORDER BY e.name, h.hostname`)
	if err != nil {
		return nil, fmt.Errorf("store: listing application hostnames: %w", err)
	}
	defer rows.Close()

	out := []ApplicationHostname{}
	for rows.Next() {
		var h ApplicationHostname
		if err := rows.Scan(&h.Hostname, &h.ApplicationID, &h.ApplicationName); err != nil {
			return nil, fmt.Errorf("store: scanning application hostname: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
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
