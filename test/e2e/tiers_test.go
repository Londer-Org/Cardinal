package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// Administration is tiered, and the tiers hold over HTTP.
//
// Policy tests prove the rules say the right thing. These prove the endpoints
// are wired to the rules — which is a separate mistake, and the one that ships.

// TestUserAdminCannotRegisterApplications.
//
// The boundary the split exists for. Whoever onboards staff must not be able to
// choose an OIDC client's redirect URIs, because that is enough to stand up a
// phishing surface inside the organisation's own identity provider.
func TestUserAdminCannotRegisterApplications(t *testing.T) {
	c, csrf := tieredClient(t, "e2e-user-admin", adminGroupUserAdmins)

	t.Run("may list people", func(t *testing.T) {
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/directory/users", "application/json")
		defer drain(resp)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
			t.Fatalf("a user-admin was refused the people list (%d): %s",
				resp.StatusCode, body)
		}
	})

	t.Run("may not list applications", func(t *testing.T) {
		resp := requestWithCSRF(t, c, http.MethodGet, "/api/applications", csrf)
		defer drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a user-admin reached the application list (%d)", resp.StatusCode)
		}
	})

	t.Run("may not register one", func(t *testing.T) {
		resp := requestWithCSRF(t, c, http.MethodPost, "/api/applications", csrf)
		defer drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a user-admin reached client registration (%d) — redirect URIs "+
				"are a phishing surface, and onboarding staff does not imply the "+
				"authority to create one", resp.StatusCode)
		}
	})
}

// TestSecurityAdminCannotManagePeople is the mirror image.
func TestSecurityAdminCannotManagePeople(t *testing.T) {
	c, csrf := tieredClient(t, "e2e-security-admin", adminGroupSecurityAdmins)

	t.Run("may list applications", func(t *testing.T) {
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/applications", "application/json")
		defer drain(resp)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
			t.Fatalf("a security-admin was refused the application list (%d): %s",
				resp.StatusCode, body)
		}
	})

	t.Run("may not list people", func(t *testing.T) {
		resp := requestWithCSRF(t, c, http.MethodGet, "/api/directory/users", csrf)
		defer drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a security-admin reached the people list (%d)", resp.StatusCode)
		}
	})

	t.Run("may not issue invitations", func(t *testing.T) {
		resp := requestWithCSRF(t, c, http.MethodPost, "/api/invitations", csrf)
		defer drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a security-admin issued an invitation (%d) — that is a "+
				"credential on someone else's account", resp.StatusCode)
		}
	})
}

// TestTiersAreReportedToTheUI.
//
// The console renders from these. Showing a user-admin a registration form they
// will be refused reads as a broken system rather than a missing permission.
func TestTiersAreReportedToTheUI(t *testing.T) {
	c, _ := tieredClient(t, "e2e-user-admin", adminGroupUserAdmins)

	resp := request(t, c, http.MethodGet, hostCardinal, "/api/auth/me", "application/json")
	defer drain(resp)

	var me struct {
		CanAdminister          bool `json:"canAdminister"`
		CanManageUsers         bool `json:"canManageUsers"`
		CanManageApplications  bool `json:"canManageApplications"`
		CanAdministerDirectory bool `json:"canAdministerDirectory"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}

	if !me.CanAdminister {
		t.Error("a user-admin was told they cannot administer anything, so the " +
			"console would hide a section they can use")
	}
	if !me.CanManageUsers {
		t.Error("canManageUsers is false for a user-admin")
	}
	if me.CanManageApplications {
		t.Error("canManageApplications is true for a user-admin — the console " +
			"would render a form they will be refused")
	}

	// The broad tier is not implied by managing users, and the console reads
	// this to decide whether to ask for the recovery queue at all. Reported
	// wrongly, a user-admin's home page requests a list it cannot have — and
	// the refusal is written to the decision log, which then describes an
	// intent that was the UI's rather than the person's.
	if me.CanAdministerDirectory {
		t.Error("canAdministerDirectory is true for a user-admin — recovery " +
			"can mint a credential on an administrator's own account, and is " +
			"deliberately out of this tier's reach")
	}
}

const (
	adminGroupUserAdmins     = "00000000-0000-7000-8000-00000000ad12"
	adminGroupSecurityAdmins = "00000000-0000-7000-8000-00000000ad13"
)

// tieredClient seeds an account holding exactly one tier.
//
// Its own account per tier, and stripped of every other membership first:
// reusing one would make each test depend on which ran before it, and a tier
// test that accidentally holds two tiers proves nothing.
func tieredClient(t *testing.T, login, groupID string) (*http.Client, string) {
	t.Helper()

	token := "e2e-" + login + "-session-token-0123456789abcdef"

	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', '`+login+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `DELETE FROM group_members
	             WHERE member_id = (SELECT id FROM entities WHERE name = '`+login+`')`)
	seedSQL(t, `INSERT INTO group_members (group_id, member_id, granted_by, valid_period)
	            SELECT '`+groupID+`', e.id, e.id, tstzrange(now(), 'infinity')
	              FROM entities e WHERE e.name = '`+login+`'`)

	seedSQL(t, `DELETE FROM sessions WHERE token_hash = sha256('`+token+`'::bytea)`)
	seedSQL(t, `INSERT INTO sessions
	              (subject_id, token_hash, valid_period, auth_method, auth_at,
	               device_bound, absolute_expiry)
	            SELECT e.id, sha256('`+token+`'::bytea),
	                   tstzrange(now(), now() + interval '1 hour'), 'passkey', now(),
	                   true, now() + interval '7 days'
	              FROM entities e WHERE e.name = '`+login+`'`)

	c := client(t)
	c.Jar.SetCookies(&url.URL{Scheme: "http", Host: hostCardinal},
		[]*http.Cookie{{Name: "cardinal_session", Value: token, Path: "/"}})

	return c, csrfToken(t, c)
}
