package e2e

import (
	"strings"
	"testing"
)

// What the journal says about a change nobody authenticated for.
//
// `cardinal grant engineers alice` used to record alice as her own granter,
// because granted_by is NOT NULL and her id was to hand. No query could tell
// that from a real self-grant, so an auditor asking "who put alice in
// engineers" was told "alice" and had no way to know the answer was invented.
//
// Attribution nobody can check is worse than none: it reads as evidence.

// TestADirectGrantIsNotRecordedAsASelfGrant.
//
// The regression this exists for, asserted against the row rather than the
// output: the CLI could print anything.
func TestADirectGrantIsNotRecordedAsASelfGrant(t *testing.T) {
	const group = "e2e-direct-actor"

	tryCardinalCLI(t, "group", "create", group)
	t.Cleanup(func() { cliBackground("revoke", group, "e2e-user") })
	tryCardinalCLI(t, "grant", group, "e2e-user", "-reason", "direct actor e2e")

	granter := seedQuery(t, `
		SELECT g.name
		  FROM group_members m
		  JOIN entities e ON e.id = m.member_id
		  JOIN entities grp ON grp.id = m.group_id
		  JOIN entities g ON g.id = m.granted_by
		 WHERE grp.name = '`+group+`' AND e.name = 'e2e-user'
		   AND m.valid_period @> now()`)

	if granter == "e2e-user" {
		t.Fatal("the grant records the member as their own granter, which is what " +
			"migration 0035 exists to stop — an auditor cannot tell this from a " +
			"real self-grant")
	}
	if granter != "direct-database" {
		t.Errorf("granted_by is %q; the command line against the database should "+
			"name direct-database", granter)
	}
}

// TestTheDirectIdentityCannotBeMistakenForAPerson.
//
// It exists to be pointed at, and an entity that could be granted things or
// signed into would be a way to launder the direct path into something that
// looks authenticated.
func TestTheDirectIdentityCannotBeMistakenForAPerson(t *testing.T) {
	row := seedQuery(t, `
		SELECT type || ' ' || system::text || ' ' || coalesce(display_name, '')
		  FROM entities WHERE name = 'direct-database'`)

	if !strings.HasPrefix(row, "service_account true") {
		t.Errorf("direct-database is %q; it should be a system service account, "+
			"which has no credentials and cannot sign in", row)
	}
	if !strings.Contains(row, "no authenticated person") {
		t.Errorf("its display name does not say what it means: %q", row)
	}

	// Passkeys are the only way to sign in, so this is the whole question.
	credentials := seedQuery(t, `
		SELECT count(*)::text FROM webauthn_credentials c
		  JOIN entities e ON e.id = c.entity_id
		 WHERE e.name = 'direct-database'`)
	if credentials != "0" {
		t.Errorf("direct-database has %s passkey(s), so something could sign in as it", credentials)
	}
}

// TestTheJournalNamesTheDirectPathForOtherChangesToo.
//
// Not only grants. Creating an entity used to record no actor at all, which is
// less wrong and still leaves an audit view with nothing to render.
func TestTheJournalNamesTheDirectPathForOtherChangesToo(t *testing.T) {
	const name = "e2e-direct-actor-user"

	tryCardinalCLI(t, "user", "create", name)

	actor := seedQuery(t, `
		SELECT coalesce(a.name, '(none)')
		  FROM events ev
		  JOIN entities e ON e.id = ev.entity_id
		  LEFT JOIN entities a ON a.id = ev.actor_id
		 WHERE e.name = '`+name+`'
		 ORDER BY ev.occurred_at DESC LIMIT 1`)

	if actor != "direct-database" {
		t.Errorf("creating a user from the command line recorded the actor as %q; "+
			"the path is known exactly, only the person is not", actor)
	}
}
