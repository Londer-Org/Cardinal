package e2e

import (
	"strings"
	"testing"
)

// What the journal says about a change nobody authenticated for.
//
// A grant made against the database used to record its own member as the
// granter, because granted_by is NOT NULL and their id was to hand. No query
// could tell that from a real self-grant, so an auditor asking "who put alice
// in engineers" was told "alice" and had no way to know the answer was
// invented.
//
// Attribution nobody can check is worse than none: it reads as evidence.

// TestNobodyIsRecordedAsHavingMadeThemselvesAnAdministrator.
//
// Asserted across the whole directory rather than against one command, because
// what matters is the state an auditor would read, and every path that can
// write this row has to hold the property: first-run setup, the seeding this
// stack does with the connection string, and the API.
//
// Grants through the API are the honest case and record the person who made
// them. A row where the member is their own granter is either a real
// self-grant — which the temporal model refuses here, since an administrator
// already holds the group they would be granting — or an actor nobody chose,
// invented because the column cannot be null.
//
// A separate test covers cardinal-server init, which is the remaining path
// that grants with nobody signed in and cannot run against this stack:
// cmd/cardinal-server/init_test.go.
func TestNobodyIsRecordedAsHavingMadeThemselvesAnAdministrator(t *testing.T) {
	rows := seedQuery(t, `
		SELECT count(*)::text
		  FROM group_members m
		  JOIN entities grp ON grp.id = m.group_id
		 WHERE grp.name = 'directory-admins'
		   AND m.valid_period @> now()`)
	if rows == "0" {
		t.Fatal("no current administrators, so this asserted nothing")
	}

	selfGranted := seedQuery(t, `
		SELECT coalesce(string_agg(e.name, ', '), '')
		  FROM group_members m
		  JOIN entities grp ON grp.id = m.group_id
		  JOIN entities e   ON e.id   = m.member_id
		 WHERE grp.name = 'directory-admins'
		   AND m.member_id = m.granted_by
		   AND m.valid_period @> now()`)

	if selfGranted != "" {
		t.Errorf("%s appear to have granted themselves directory-admins; "+
			"whatever wrote those rows had no authenticated person and should "+
			"have said so", selfGranted)
	}
}

// TestAGrantThroughTheAPINamesThePersonWhoMadeIt.
//
// The other half: naming the direct path is only honest because the path that
// does have somebody behind it names them. A handler that recorded
// direct-database for an authenticated request would make every grant
// unattributable while still passing the test above.
func TestAGrantThroughTheAPINamesThePersonWhoMadeIt(t *testing.T) {
	const group = "e2e-direct-actor"

	createFixture(t, "group", group)
	t.Cleanup(func() { revokeAfterwards(group, "e2e-user") })
	grantFixture(t, group, "e2e-user", "direct actor e2e")

	granter := seedQuery(t, `
		SELECT g.name
		  FROM group_members m
		  JOIN entities e   ON e.id   = m.member_id
		  JOIN entities grp ON grp.id = m.group_id
		  JOIN entities g   ON g.id   = m.granted_by
		 WHERE grp.name = '`+group+`' AND e.name = 'e2e-user'
		   AND m.valid_period @> now()`)

	if granter == "direct-database" {
		t.Fatal("a grant made over the API with a session recorded the direct " +
			"path; there was a person, and the journal should name them")
	}
	if granter != adminLogin {
		t.Errorf("granted_by is %q; the fixture signs in as %s", granter, adminLogin)
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
// Not only grants. A change made against the database used to record no actor
// at all, which is less wrong than inventing one and still leaves an audit view
// with nothing to render.
//
// Asserted through invitations, which are still a direct command and are the
// sharpest case left: an invitation is a credential, and "somebody with the
// connection string issued one" is exactly what the journal has to be able to
// say. Entity creation used to be the subject here and has moved onto the API,
// where it records the person instead.
func TestTheJournalNamesTheDirectPathForOtherChangesToo(t *testing.T) {
	const name = "e2e-direct-actor-user"

	createFixture(t, "user", name)
	tryCardinalCLI(t, "invite", name)

	actor := seedQuery(t, `
		SELECT coalesce(a.name, '(none)')
		  FROM events ev
		  JOIN entities e ON e.id = ev.entity_id
		  LEFT JOIN entities a ON a.id = ev.actor_id
		 WHERE e.name = '`+name+`' AND ev.action = 'invitation.issued'
		 ORDER BY ev.occurred_at DESC LIMIT 1`)

	if actor == "(none)" {
		t.Fatal("issuing an invitation from the command line recorded no actor; " +
			"an audit view has nothing to render for the change that hands " +
			"somebody a way in")
	}
	if actor != "direct-database" {
		t.Errorf("it recorded the actor as %q; the path is known exactly, only "+
			"the person is not", actor)
	}
}
