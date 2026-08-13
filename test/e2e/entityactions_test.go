package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Actions on things the console could already show but not change.
//
// Two of these had no implementation anywhere, and both are claims the project
// makes elsewhere: that renaming is an ordinary edit rather than a migration,
// and that a leaked client secret can be dealt with.

// TestRenamingMovesNothingElse.
//
// The README's first line against LDAP is that the DN *is* the identity there,
// so renaming breaks every reference — whereas here identity is an immutable
// UUIDv7 and the name is an attribute. That was true of the schema and of
// nothing else: no store method, no endpoint, no button.
//
// So the assertions are about what survives. A group membership granted before
// the rename is still a membership afterwards, because it references the id;
// if any of this were keyed by name, that is what would break.
func TestRenamingMovesNothingElse(t *testing.T) {
	const before = "e2e-rename-before"
	const after = "e2e-rename-after"

	// Both names free, since the stack outlives a run and the previous one left
	// the account under the second name.
	//
	// Memberships first: this test grants one, and entities is referenced by
	// group_members, so deleting the account outright is refused — correctly,
	// and by the constraint that makes a grant survive a rename in the first
	// place.
	seedSQL(t, `DELETE FROM group_members
	             WHERE member_id IN (SELECT id FROM entities
	                                  WHERE type = 'user' AND name IN ('`+before+`', '`+after+`'))`)
	seedSQL(t, `DELETE FROM entities WHERE type = 'user' AND name IN ('`+before+`', '`+after+`')`)
	tryCardinalCLI(t, "user", "create", before)
	tryCardinalCLI(t, "group", "create", "e2e-rename-group")
	grantFixture(t, "e2e-rename-group", before)

	id := seedQuery(t, `SELECT id FROM entities WHERE type = 'user' AND name = '`+before+`'`)
	if id == "" {
		t.Fatal("the fixture account was not created")
	}

	admin, csrf := adminClient(t)

	resp, err := admin.Do(jsonRequest(t, http.MethodPost,
		"/api/directory/users/"+before+"/rename", csrf, map[string]string{"name": after}))
	if err != nil {
		t.Fatal(err)
	}
	drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("renaming returned %d", resp.StatusCode)
	}

	// The identifier is the same row.
	if now := seedQuery(t,
		`SELECT id FROM entities WHERE type = 'user' AND name = '`+after+`'`); now != id {
		t.Fatalf("the renamed account has id %q, was %q — this is a new row, "+
			"which is exactly what a rename must not be", now, id)
	}

	// And the membership came with it, because it references the id.
	detail := userDetail(t, admin, after)
	found := false
	for _, m := range detail.Memberships {
		if m.Group == "e2e-rename-group" {
			found = true
		}
	}
	if !found {
		t.Fatal("the group membership did not survive the rename — something is " +
			"keyed by name")
	}

	// The old name is free again, which is what makes a rename an edit rather
	// than a reservation.
	tryCardinalCLI(t, "user", "create", before)
	if seedQuery(t, `SELECT count(*) FROM entities WHERE type = 'user' AND name = '`+before+`'`) != "1" {
		t.Error("the old name could not be reused after the rename")
	}
}

// TestRenamingRefusesACollisionAndSystemGroups.
func TestRenamingRefusesACollisionAndSystemGroups(t *testing.T) {
	tryCardinalCLI(t, "user", "create", "e2e-rename-a")
	tryCardinalCLI(t, "user", "create", "e2e-rename-b")

	admin, csrf := adminClient(t)

	t.Run("a name somebody else holds", func(t *testing.T) {
		resp, err := admin.Do(jsonRequest(t, http.MethodPost,
			"/api/directory/users/e2e-rename-a/rename", csrf,
			map[string]string{"name": "e2e-rename-b"}))
		if err != nil {
			t.Fatal(err)
		}
		defer drain(resp)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("got %d, want 409 — two accounts cannot share a login",
				resp.StatusCode)
		}
	})

	t.Run("a system group", func(t *testing.T) {
		name := seedQuery(t,
			`SELECT name FROM entities WHERE id = '`+adminGroupID+`'`)
		if name == "" {
			t.Skip("the admin group is not in this database")
		}

		resp, err := admin.Do(jsonRequest(t, http.MethodPost,
			"/api/directory/groups/"+name+"/rename", csrf,
			map[string]string{"name": "e2e-renamed-system-group"}))
		if err != nil {
			t.Fatal(err)
		}
		defer drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("got %d, want 403 — policy finds system groups by id, but "+
				"people find them by name", resp.StatusCode)
		}
	})
}

// TestRotatingAClientSecretInvalidatesTheOldOne.
//
// There was no way to do this at all. A secret that leaked could only be dealt
// with by disabling the application and registering a new one, which changes
// the client id — a reconfiguration of the application in response to an
// incident, at the worst possible moment.
//
// The assertion that matters is not that a new secret comes back. It is that
// the old one stops authenticating, which is checked by using both against an
// endpoint that authenticates the client: a wrong secret is invalid_client, a
// right one gets as far as invalid_grant.
func TestRotatingAClientSecretInvalidatesTheOldOne(t *testing.T) {
	clientID, secret := registerConfidentialClient(t, "e2e-rotate-secret")

	if got := clientAuthError(t, clientID, secret); got != "invalid_grant" {
		t.Fatalf("the original secret did not authenticate (%q) — the rest of "+
			"this test cannot tell a working rotation from a broken fixture", got)
	}

	admin, csrf := adminClient(t)
	var rotated struct {
		Secret string `json:"secret"`
	}
	resp := postJSON(t, admin, "/api/applications/"+clientID+"/secret", csrf, nil, &rotated) //nolint:bodyclose // the helper drains and closes it; bodyclose cannot see through the call
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotating returned %d", resp.StatusCode)
	}
	if rotated.Secret == "" || rotated.Secret == secret {
		t.Fatal("the rotation returned the same secret, or none")
	}

	if got := clientAuthError(t, clientID, secret); got != "invalid_client" {
		t.Fatalf("the old secret still authenticates (%q) — a rotation that "+
			"leaves the leaked value working is not a rotation", got)
	}
	if got := clientAuthError(t, clientID, rotated.Secret); got != "invalid_grant" {
		t.Fatalf("the new secret does not authenticate (%q) — the application "+
			"cannot be reconfigured back into service", got)
	}
}

// clientAuthError asks the token endpoint to authenticate a client.
//
// A refresh_token grant with a bogus token: the client is authenticated first,
// so the error distinguishes "wrong secret" (invalid_client) from "right
// secret, bad grant" (invalid_grant). Nothing else on the token endpoint
// separates the two.
func clientAuthError(t *testing.T, clientID, secret string) string {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		origin(hostCardinal)+"/oidc/token",
		strings.NewReader("grant_type=refresh_token&refresh_token=not-a-real-token"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)

	resp, err := client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding the token error: %v", err)
	}
	return body.Error
}

// TestAssigningAPOSIXIdentityFromTheConsole.
//
// Without one, a host cannot resolve the account at all, so nobody can log into
// a machine as them however the policy is written.
func TestAssigningAPOSIXIdentityFromTheConsole(t *testing.T) {
	const login = "e2e-posix-console"
	tryCardinalCLI(t, "user", "create", login)

	admin, csrf := adminClient(t)

	var assigned struct {
		UID           int    `json:"uid"`
		HomeDirectory string `json:"homeDirectory"`
		LoginShell    string `json:"loginShell"`
	}
	req := jsonRequest(t, http.MethodPut, "/api/directory/users/"+login+"/posix", csrf,
		map[string]string{"homeDirectory": "/home/" + login, "loginShell": "/bin/zsh"})
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("assigning returned %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&assigned); err != nil {
		t.Fatal(err)
	}

	if assigned.UID == 0 {
		t.Fatal("no uid was allocated")
	}
	if assigned.LoginShell != "/bin/zsh" {
		t.Errorf("login shell is %q, want the one that was sent", assigned.LoginShell)
	}

	// And the detail view reports it, which is where somebody would look.
	if detail := userDetail(t, admin, login); detail.POSIX == nil {
		t.Fatal("the account page shows no POSIX identity after one was assigned")
	} else if detail.POSIX.UID != assigned.UID {
		t.Errorf("the page shows uid %d, the assignment returned %d",
			detail.POSIX.UID, assigned.UID)
	}
}

// TestAnAdministratorCanCorrectSomebodyElsesDetails.
//
// The corrections people cannot make themselves: a name typed wrong at
// onboarding, an address that bounces. Deliberately cannot touch the login,
// which has its own endpoint and its own consequences.
func TestAnAdministratorCanCorrectSomebodyElsesDetails(t *testing.T) {
	const login = "e2e-admin-edits"
	tryCardinalCLI(t, "user", "create", login)

	admin, csrf := adminClient(t)

	var updated struct {
		DisplayName string `json:"displayName"`
	}
	resp := jsonRequest(t, http.MethodPatch, "/api/directory/users/"+login, csrf,
		map[string]string{"displayName": "Corrected Name"})
	got, err := admin.Do(resp)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(got)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("updating returned %d", got.StatusCode)
	}
	if err := json.NewDecoder(got.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "Corrected Name" {
		t.Fatalf("display name is %q", updated.DisplayName)
	}

	// The login is untouched, which is the whole reason this is a separate
	// endpoint from renaming.
	if detail := userDetail(t, admin, login); detail.Login != login {
		t.Fatalf("the login changed to %q", detail.Login)
	}
}

// registerConfidentialClient registers one and returns its id and secret.
//
// Through the CLI, because the secret is shown once at registration and the
// console's registration dialog is not what these tests are about.
func registerConfidentialClient(t *testing.T, name string) (clientID, secret string) {
	t.Helper()

	// A fresh one each run: the secret is only ever shown at registration, so a
	// client left over from a previous run is one whose secret nobody has.
	seedSQL(t, `DELETE FROM oidc_clients
	             WHERE entity_id IN (SELECT id FROM entities
	                                  WHERE type = 'application' AND name = '`+name+`')`)
	seedSQL(t, `DELETE FROM entities WHERE type = 'application' AND name = '`+name+`'`)

	out := cardinalCLI(t, "app", "register", name,
		"-display", name,
		"-redirect", "https://"+name+".example.com/callback",
		"-confidential",
		"-config", "/etc/cardinal/cardinal.toml")

	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "client_id":
			clientID = fields[1]
		case "client_secret":
			secret = fields[1]
		}
	}
	if clientID == "" || secret == "" {
		t.Fatalf("no client id or secret in:\n%s", out)
	}
	return clientID, secret
}

type userDetailBody struct {
	Login       string `json:"login"`
	DisplayName string `json:"displayName"`
	Memberships []struct {
		Group string `json:"group"`
	} `json:"memberships"`
	POSIX *struct {
		UID        int    `json:"uid"`
		LoginShell string `json:"loginShell"`
	} `json:"posix"`
}

func userDetail(t *testing.T, c *http.Client, login string) userDetailBody {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/users/"+login, "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reading %s returned %d", login, resp.StatusCode)
	}

	var out userDetailBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
