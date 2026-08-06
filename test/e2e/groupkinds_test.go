package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// System groups confer authority within Cardinal; the rest are ordinary
// directory data an application cares about.
//
// Treating them alike was an escalation. Granting membership is ManageUsers, so
// a user-admin could grant themselves directory-admins and become one — which
// made the tiers decorative for as long as the distinction did not exist.

// TestUserAdminCannotSelfPromote is the regression test for that.
func TestUserAdminCannotSelfPromote(t *testing.T) {
	adminClient(t)
	c, csrf := tieredClient(t, "e2e-user-admin", adminGroupUserAdmins)

	for _, group := range []string{"directory-admins", "user-admins", "security-admins"} {
		t.Run("cannot grant "+group, func(t *testing.T) {
			resp := postRaw(t, c, csrf,
				"/api/directory/groups/"+group+"/members",
				`{"member":"e2e-user-admin","reason":"probe"}`)
			defer drain(resp)
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("a user-admin granted itself %s (%d): %s — the tier "+
					"boundary is decorative if the narrow tier can hand itself "+
					"the broad one", group, resp.StatusCode, body)
			}
		})
	}

	t.Run("cannot revoke one either", func(t *testing.T) {
		resp := requestWithCSRF(t, c, http.MethodDelete,
			"/api/directory/groups/directory-admins/members/e2e-admin", csrf)
		defer drain(resp)

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a user-admin revoked an administrator (%d) — not an "+
				"escalation, but a denial of service on the directory",
				resp.StatusCode)
		}
	})
}

// TestUserAdminManagesOrdinaryGroups.
//
// The other half: the split must not stop a user-admin doing the job the tier
// exists for. Application groups are ordinary directory data.
func TestUserAdminManagesOrdinaryGroups(t *testing.T) {
	adminClient(t)
	c, csrf := tieredClient(t, "e2e-user-admin", adminGroupUserAdmins)

	const group = "e2e-aura-users"
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('group', '`+group+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', 'e2e-aura-member')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `DELETE FROM group_members
	             WHERE group_id = (SELECT id FROM entities WHERE name = '`+group+`')`)

	resp := postRaw(t, c, csrf, "/api/directory/groups/"+group+"/members",
		`{"member":"e2e-aura-member","reason":"ordinary group"}`)
	defer drain(resp)

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("a user-admin could not manage an application group (%d): %s — "+
			"that is the job the tier exists for", resp.StatusCode, body)
	}
}

// TestSystemGroupsAreMarked.
//
// The console needs to show which groups confer authority, or an administrator
// cannot tell `aura-admins` from `directory-admins` by looking.
func TestSystemGroupsAreMarked(t *testing.T) {
	c, _ := adminClient(t)

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/groups?limit=100", "application/json")
	defer drain(resp)

	var page struct {
		Items []struct {
			Name   string `json:"name"`
			System bool   `json:"system"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatal(err)
	}

	kinds := map[string]bool{}
	for _, g := range page.Items {
		kinds[g.Name] = g.System
	}

	for _, name := range []string{"directory-admins", "user-admins", "security-admins"} {
		if !kinds[name] {
			t.Errorf("%s is not marked as a system group", name)
		}
	}
	if kinds["e2e-aura-users"] {
		t.Error("an ordinary application group was marked as a system group")
	}
}

// TestUserAdminCanSeeApplicationNames.
//
// The tier that creates groups has to name an application to associate one
// with, so it needs the list to choose from — while still being refused the
// registrations themselves, which is a different question and a different tier.
func TestUserAdminCanSeeApplicationNames(t *testing.T) {
	adminClient(t)
	c, csrf := tieredClient(t, "e2e-user-admin", adminGroupUserAdmins)

	t.Run("may list application names", func(t *testing.T) {
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/directory/applications", "application/json")
		defer drain(resp)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("a user-admin was refused the application names (%d): %s — "+
				"the owner picker would then be empty for exactly the tier that "+
				"creates groups", resp.StatusCode, body)
		}

		var page struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			for _, leaked := range []string{"redirectUris", "clientId", "scopes"} {
				if _, present := item[leaked]; present {
					t.Errorf("the reference listing exposes %q — it should be "+
						"names only, or it widens access for a dropdown's sake",
						leaked)
				}
			}
		}
	})

	t.Run("still may not read registrations", func(t *testing.T) {
		resp := requestWithCSRF(t, c, http.MethodGet, "/api/applications", csrf)
		defer drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a user-admin read the application registrations (%d)",
				resp.StatusCode)
		}
	})
}

// TestGroupKindFilter narrows a listing to one category.
func TestGroupKindFilter(t *testing.T) {
	c, _ := adminClient(t)

	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('group', 'e2e-plain-group')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL, owner_id = NULL`)

	names := func(kind string) []string {
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/directory/groups?limit=100&kind="+kind, "application/json")
		defer drain(resp)

		var page struct {
			Items []struct {
				Name   string `json:"name"`
				System bool   `json:"system"`
				Owner  string `json:"owner"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			t.Fatal(err)
		}
		if page.Total != len(page.Items) {
			t.Errorf("kind=%q reports %d total but returned %d — a total that "+
				"counts different rows than the page is worse than no total",
				kind, page.Total, len(page.Items))
		}
		out := make([]string, 0, len(page.Items))
		for _, g := range page.Items {
			out = append(out, g.Name)
		}
		return out
	}

	system := names("system")
	if !contains(system, "directory-admins") {
		t.Errorf("kind=system omitted directory-admins: %v", system)
	}
	if contains(system, "e2e-plain-group") {
		t.Errorf("kind=system included an ordinary group: %v", system)
	}

	plain := names("plain")
	if !contains(plain, "e2e-plain-group") {
		t.Errorf("kind=plain omitted an ordinary group: %v", plain)
	}
	if contains(plain, "directory-admins") {
		t.Errorf("kind=plain included a system group: %v", plain)
	}

	// A typo should not look like an empty directory.
	if len(names("nonsense")) < len(names("")) {
		t.Error("an unrecognised filter hid rows rather than showing everything")
	}
}
