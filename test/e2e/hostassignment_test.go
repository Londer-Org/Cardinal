package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/agent"
	"github.com/arthur-lonfils/cardinal/internal/hostclient"
	"github.com/arthur-lonfils/cardinal/internal/sudoers"
)

// What a host is allowed to know.
//
// The property under test is a negative one, and it is the difference between
// this and an LDAP-bound host: compromising the least important machine in the
// fleet must not yield the whole directory. So each test asserts both halves —
// the permitted person is there, and the unpermitted one is not — because
// either alone passes for the wrong reasons.

type assignmentUser struct {
	Name   string `json:"name"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Home   string `json:"home"`
	Shell  string `json:"shell"`
	Groups []int  `json:"groups"`
	Sudo   bool   `json:"sudo"`
}

type assignmentGroup struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

type assignmentBody struct {
	Host       string            `json:"host"`
	Users      []assignmentUser  `json:"users"`
	Groups     []assignmentGroup `json:"groups"`
	Unnumbered []string          `json:"unnumbered"`
}

func (a assignmentBody) user(name string) (assignmentUser, bool) {
	for _, u := range a.Users {
		if u.Name == name {
			return u, true
		}
	}
	return assignmentUser{}, false
}

func (a assignmentBody) names() []string {
	out := make([]string, 0, len(a.Users))
	for _, u := range a.Users {
		out = append(out, u.Name)
	}
	slices.Sort(out)
	return out
}

// hostAccessFixture seeds a group of people, a group of machines, and a policy
// letting the first log into the second under their own names.
//
// Returns the group id of the people, so a test can move somebody in or out.
func hostAccessFixture(t *testing.T) (restore func()) {
	t.Helper()

	tryCardinalCLI(t, "group", "create", "e2e-linux-users")
	tryCardinalCLI(t, "group", "create", "e2e-linux-hosts")
	tryCardinalCLI(t, "group", "create", "e2e-linux-admins")
	tryCardinalCLI(t, "grant", "e2e-linux-admins", "e2e-sysadmin")

	// Permitted, and given a uid.
	tryCardinalCLI(t, "user", "create", "e2e-sysadmin")
	tryCardinalCLI(t, "posix", "assign", "user", "e2e-sysadmin")
	tryCardinalCLI(t, "grant", "e2e-linux-users", "e2e-sysadmin")

	// May log in and may not sudo. Without them, "everybody gets root" and
	// "the right people get root" are the same passing test.
	tryCardinalCLI(t, "user", "create", "e2e-nonroot")
	tryCardinalCLI(t, "posix", "assign", "user", "e2e-nonroot")
	tryCardinalCLI(t, "grant", "e2e-linux-users", "e2e-nonroot")

	// Has a uid and no grant at all. The one that proves the host is not simply
	// being handed every numbered account in the directory.
	tryCardinalCLI(t, "user", "create", "e2e-outsider")
	tryCardinalCLI(t, "posix", "assign", "user", "e2e-outsider")

	// A group with a gid, so memberships project to numbers.
	tryCardinalCLI(t, "posix", "assign", "group", "e2e-linux-users")

	usersGroup := seedQuery(t,
		`SELECT id FROM entities WHERE type = 'group' AND name = 'e2e-linux-users'`)
	hostsGroup := seedQuery(t,
		`SELECT id FROM entities WHERE type = 'group' AND name = 'e2e-linux-hosts'`)
	adminsGroup := seedQuery(t,
		`SELECT id FROM entities WHERE type = 'group' AND name = 'e2e-linux-admins'`)
	if usersGroup == "" || hostsGroup == "" || adminsGroup == "" {
		t.Fatal("fixture groups were not created")
	}

	return publishPolicy(t, hostAccessPolicy(usersGroup, hostsGroup, adminsGroup))
}

// enrolledHostInGroup enrols a machine and puts it in the group the policy names.
func enrolledHostInGroup(t *testing.T, name string) *hostclient.Identity {
	t.Helper()

	tryCardinalCLI(t, "host", "create", name)
	tryCardinalCLI(t, "grant", "e2e-linux-hosts", name)

	return enrolledHost(t, name)
}

func fetchAssignment(t *testing.T, identity *hostclient.Identity) assignmentBody {
	t.Helper()

	resp := signedGET{signer: identity.Signer, path: "/api/hosts/assignment"}.send(t)
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200 from /api/hosts/assignment", resp.StatusCode)
	}

	var out assignmentBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHostLearnsOnlyThePeopleWhoMayLogIntoIt.
//
// The whole reason this endpoint exists rather than the host reading the
// directory. Both assertions matter: without the first the endpoint could be
// returning nothing at all, and without the second it could be returning
// everybody.
func TestHostLearnsOnlyThePeopleWhoMayLogIntoIt(t *testing.T) {
	defer hostAccessFixture(t)()

	host := enrolledHostInGroup(t, "e2e-linux-01")

	assignment := fetchAssignment(t, host)

	sysadmin, ok := assignment.user("e2e-sysadmin")
	if !ok {
		t.Fatalf("e2e-sysadmin is missing; the host was told about %v", assignment.names())
	}
	if sysadmin.UID < 65536 {
		t.Fatalf("uid %d is inside the system's own range", sysadmin.UID)
	}
	if sysadmin.GID != sysadmin.UID {
		t.Fatalf("primary gid %d is not the user-private group %d",
			sysadmin.GID, sysadmin.UID)
	}
	if sysadmin.Home != "/home/e2e-sysadmin" || sysadmin.Shell == "" {
		t.Fatalf("incomplete record: %+v", sysadmin)
	}

	if _, leaked := assignment.user("e2e-outsider"); leaked {
		t.Fatal("a user with no grant on this host was disclosed to it — " +
			"this is the LDAP enumeration failure the design exists to avoid")
	}

	// The seeded administrator has no host grant either, and is the account
	// whose disclosure would matter most.
	if _, leaked := assignment.user("e2e-admin"); leaked {
		t.Fatal("the directory administrator was disclosed to a host")
	}
}

// TestAHostNotInTheGroupLearnsNobody.
//
// Same policy, same people, a machine the rule does not reach. The resource
// side of the decision has to matter as much as the principal side — a host
// that got everyone's records merely by enrolling would make the grant
// meaningless.
func TestAHostNotInTheGroupLearnsNobody(t *testing.T) {
	defer hostAccessFixture(t)()

	// Enrolled, authenticated, and simply not in e2e-linux-hosts.
	stranger := enrolledHost(t, "e2e-linux-99")

	assignment := fetchAssignment(t, stranger)

	if len(assignment.Users) != 0 {
		t.Fatalf("a host outside the group was told about %v", assignment.names())
	}
}

// TestGroupsCarryTheirGidAndMembers.
//
// `id alice` has to name the groups, not just the numbers, so the records have
// to travel together. Only groups somebody here belongs to: a group nobody on
// this machine is in is one more name it has no reason to learn.
func TestGroupsCarryTheirGidAndMembers(t *testing.T) {
	defer hostAccessFixture(t)()

	host := enrolledHostInGroup(t, "e2e-linux-02")
	assignment := fetchAssignment(t, host)

	var found *assignmentGroup
	for i := range assignment.Groups {
		if assignment.Groups[i].Name == "e2e-linux-users" {
			found = &assignment.Groups[i]
		}
	}
	if found == nil {
		t.Fatalf("e2e-linux-users is missing from %+v", assignment.Groups)
	}
	if !slices.Contains(found.Members, "e2e-sysadmin") {
		t.Fatalf("e2e-sysadmin is not listed in %+v", found)
	}

	sysadmin, _ := assignment.user("e2e-sysadmin")
	if !slices.Contains(sysadmin.Groups, found.GID) {
		t.Fatalf("the user's supplementary groups %v do not include gid %d",
			sysadmin.Groups, found.GID)
	}
}

// TestPermittedUsersWithoutNumbersAreReported.
//
// The silent failure this field exists to prevent: policy says yes, a
// certificate is issued, and sshd rejects the login because the host cannot
// resolve the name. Nothing in that chain says why.
func TestPermittedUsersWithoutNumbersAreReported(t *testing.T) {
	defer hostAccessFixture(t)()

	// Permitted, deliberately never given a uid.
	tryCardinalCLI(t, "user", "create", "e2e-nouid")
	tryCardinalCLI(t, "grant", "e2e-linux-users", "e2e-nouid")

	host := enrolledHostInGroup(t, "e2e-linux-03")
	assignment := fetchAssignment(t, host)

	if !slices.Contains(assignment.Unnumbered, "e2e-nouid") {
		t.Fatalf("a permitted user with no uid was not reported: %v", assignment.Unnumbered)
	}
	if _, ok := assignment.user("e2e-nouid"); ok {
		t.Fatal("a user with no uid was served as though they had one")
	}
}

// hostAccessPolicy is the shipped policy with the host rule pointed at real
// groups.
//
// Written out rather than patched, because the shipped file's identifiers are
// placeholders that match nothing — a test that inherited them would pass
// against a rule that can never fire.
func hostAccessPolicy(usersGroup, hostsGroup, adminsGroup string) string {
	return fmt.Sprintf(`
@id("staff-web-access")
permit (
    principal,
    action == Cardinal::Action::"AccessURL",
    resource
)
when {
    context has audience && context.audience == "staff"
};

@id("any-user-may-access-any-application")
permit (
    principal,
    action == Cardinal::Action::"AccessApplication",
    resource
);

// Every action the shipped rule of this name covers, not just the first.
//
// It listed AdministerDirectory alone, which quietly made this fixture a
// stricter world than the real policy set: anything behind ManageUsers — the
// tier people, groups and hosts sit on — was denied to an administrator while
// the fixture was active. No test noticed until one wanted to read a host page
// with an admin session, because none of them had reason to.
@id("directory-admins-may-administer")
permit (
    principal in Cardinal::Group::"00000000-0000-7000-8000-00000000ad11",
    action in [
        Cardinal::Action::"AdministerDirectory",
        Cardinal::Action::"ManageUsers",
        Cardinal::Action::"ManageApplications"
    ],
    resource
);

@id("admin-requires-fresh-device-bound-auth")
forbid (
    principal,
    action in [Cardinal::Action::"AdministerDirectory",
               Cardinal::Action::"ManageUsers",
               Cardinal::Action::"ManageApplications"],
    resource
)
unless {
    principal.deviceBound && principal.authAgeSeconds <= 300
};

// The rule under test. Kept alongside the device-bound forbid below on purpose:
// the assignment endpoint has no session to evaluate, so if it did not
// deliberately evaluate as-if-authenticated, that forbid would empty every
// assignment and every one of these tests would fail rather than quietly pass.
@id("engineers-may-log-into-development")
permit (
    principal in Cardinal::Group::%q,
    action == Cardinal::Action::"SSHLogin",
    resource in Cardinal::Group::%q
)
when {
    context.localAccount == principal.login
};

@id("ssh-requires-device-bound")
forbid (
    principal,
    action == Cardinal::Action::"SSHLogin",
    resource
)
unless {
    principal.deviceBound
};

@id("platform-admins-may-run-as-root")
permit (
    principal in Cardinal::Group::%q,
    action == Cardinal::Action::"RunAsRoot",
    resource in Cardinal::Group::%q
);

// Kept alongside, for the same reason as the SSH one: the renderer has no
// session to evaluate, so without the deliberate as-if-authenticated
// substitution this forbid empties every sudoers file and the test below fails
// rather than quietly passing.
@id("root-requires-recent-auth")
forbid (
    principal,
    action == Cardinal::Action::"RunAsRoot",
    resource
)
unless {
    principal.authAgeSeconds <= 900
};
`, usersGroup, hostsGroup, adminsGroup, hostsGroup)
}

// TestSudoIsDecidedSeparatelyFromLoggingIn.
//
// Two grants, two answers. A host that marked everyone who may log in as a
// sudoer would pass any test that only checked the admin, so the person who may
// log in and may not sudo is what makes this mean anything.
func TestSudoIsDecidedSeparatelyFromLoggingIn(t *testing.T) {
	defer hostAccessFixture(t)()

	host := enrolledHostInGroup(t, "e2e-linux-04")
	assignment := fetchAssignment(t, host)

	admin, ok := assignment.user("e2e-sysadmin")
	if !ok {
		t.Fatalf("e2e-sysadmin is missing; the host was told about %v", assignment.names())
	}
	if !admin.Sudo {
		t.Fatal("a member of the admin group was not marked as a sudoer")
	}

	plain, ok := assignment.user("e2e-nonroot")
	if !ok {
		t.Fatalf("e2e-nonroot is missing; the host was told about %v", assignment.names())
	}
	if plain.Sudo {
		t.Fatal("somebody with no RunAsRoot grant was marked as a sudoer")
	}
}

// TestTheRenderedSudoersFileNamesOnlyTheSudoers.
//
// The assignment and the file are separate steps, and a renderer that ignored
// the flag would still produce something visudo accepts.
func TestTheRenderedSudoersFileNamesOnlyTheSudoers(t *testing.T) {
	defer hostAccessFixture(t)()

	host := enrolledHostInGroup(t, "e2e-linux-05")
	assignment := fetchAssignment(t, host)

	cached := &agent.Assignment{Host: "e2e-linux-05"}
	for _, u := range assignment.Users {
		cached.Users = append(cached.Users, agent.AssignedUser{Name: u.Name, Sudo: u.Sudo})
	}

	rendered, err := sudoers.Render(cached.Sudoers(), cached.Host, time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(rendered), "e2e-sysadmin ALL=") {
		t.Fatalf("the admin is not in the file:\n%s", rendered)
	}
	if strings.Contains(string(rendered), "e2e-nonroot ALL=") {
		t.Fatalf("a non-sudoer was written into the file:\n%s", rendered)
	}
	if strings.Contains(string(rendered), "e2e-outsider") {
		t.Fatalf("somebody with no access to this host at all is in the file:\n%s", rendered)
	}
}

// TestServingAnAssignmentClosesTheAdoptionWindow.
//
// The guard on adopting a number is a column, and the column is only meaningful
// if the endpoint that hands numbers out actually sets it. Without this the
// whole safety property is decorative: `posix adopt` would keep saying yes long
// after machines had written the number to their filesystems.
func TestServingAnAssignmentClosesTheAdoptionWindow(t *testing.T) {
	defer hostAccessFixture(t)()

	tryCardinalCLI(t, "user", "create", "e2e-adoptme")
	tryCardinalCLI(t, "posix", "assign", "user", "e2e-adoptme")
	tryCardinalCLI(t, "grant", "e2e-linux-users", "e2e-adoptme")

	// Established rather than assumed. The stack outlives a `go test` run, so on
	// the second run this identity has already been served by the first — which
	// is exactly what the test is about to check for, and would make it pass or
	// fail depending on history rather than on behaviour.
	seedSQL(t, `
		UPDATE posix_identities SET first_served_at = NULL
		 WHERE entity_id = (SELECT id FROM entities WHERE name = 'e2e-adoptme')`)

	before := seedQuery(t, `
		SELECT first_served_at IS NULL FROM posix_identities p
		  JOIN entities e ON e.id = p.entity_id
		 WHERE e.name = 'e2e-adoptme'`)
	if before != "t" {
		t.Fatalf("a freshly assigned number is already marked served (%q)", before)
	}

	host := enrolledHostInGroup(t, "e2e-linux-06")
	assignment := fetchAssignment(t, host)
	if _, ok := assignment.user("e2e-adoptme"); !ok {
		t.Fatalf("the fixture user was not in the assignment: %v", assignment.names())
	}

	after := seedQuery(t, `
		SELECT first_served_at IS NULL FROM posix_identities p
		  JOIN entities e ON e.id = p.entity_id
		 WHERE e.name = 'e2e-adoptme'`)
	if after != "f" {
		t.Fatal("a number was handed to a host and not marked as served — " +
			"it could still be changed after the machine wrote it to disk")
	}

	// And the group's gid too. A directory group's number is on files just as a
	// user's is, and serving it in the same response has to close its window as
	// well. Cleared and re-served in one go for the same reason as above.
	seedSQL(t, `
		UPDATE posix_identities SET first_served_at = NULL
		 WHERE entity_id = (SELECT id FROM entities WHERE name = 'e2e-linux-users')`)
	drain(signedGET{signer: host.Signer, path: "/api/hosts/assignment"}.send(t))

	group := seedQuery(t, `
		SELECT first_served_at IS NULL FROM posix_identities p
		  JOIN entities e ON e.id = p.entity_id
		 WHERE e.name = 'e2e-linux-users'`)
	if group != "f" {
		t.Fatal("a gid was served to a host and left adoptable")
	}
}
