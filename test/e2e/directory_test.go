package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// Managing people and groups over the admin API.
//
// The temporal half is what matters here: a grant carries a period, and the
// property worth proving is that an expired one stops counting without anything
// having run. That is the claim the whole data model rests on.

func TestDirectoryRequiresAdmin(t *testing.T) {
	adminClient(t) // ensures the ordinary account is not an administrator
	c := signedInClient(t)

	for _, path := range []string{"/api/directory/users", "/api/directory/groups"} {
		resp := request(t, c, http.MethodGet, hostCardinal, path, "application/json")
		drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s returned %d for an ordinary user, want 403", path, resp.StatusCode)
		}
	}
}

// TestGrantAndRevokeMembership walks what an administrator actually does.
func TestGrantAndRevokeMembership(t *testing.T) {
	c, csrf := adminClient(t)

	const (
		login = "e2e-member"
		group = "e2e-squad"
	)
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', '`+login+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('group', '`+group+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `DELETE FROM group_members
	             WHERE group_id = (SELECT id FROM entities WHERE name = '`+group+`')`)

	until := time.Now().Add(14 * 24 * time.Hour).UTC().Format(time.RFC3339)
	//nolint:bodyclose // postJSON closes the body before returning
	postJSON(t, c, "/api/directory/groups/"+group+"/members", csrf, map[string]any{
		"member": login,
		"until":  until,
		"reason": "incident 4412",
	}, nil)

	members := groupMembers(t, c, group)
	if len(members) != 1 {
		t.Fatalf("expected one member, got %d", len(members))
	}
	if members[0].Until == nil {
		t.Error("a bounded grant came back unbounded — the period was dropped")
	}
	if members[0].Reason != "incident 4412" {
		t.Errorf("reason = %q, want it preserved; it is what an auditor reads",
			members[0].Reason)
	}

	// It shows on the person too.
	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/users/"+login, "application/json")
	defer drain(resp)
	var user struct {
		Memberships []struct {
			Group string `json:"group"`
		} `json:"memberships"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	if len(user.Memberships) != 1 || user.Memberships[0].Group != group {
		t.Errorf("the membership is not visible from the person: %+v", user.Memberships)
	}

	// Revoking removes it from the current list.
	revoked := requestWithCSRF(t, c, http.MethodDelete,
		"/api/directory/groups/"+group+"/members/"+login, csrf)
	drain(revoked)
	if revoked.StatusCode != http.StatusNoContent {
		t.Fatalf("revoking returned %d, want 204", revoked.StatusCode)
	}

	if after := groupMembers(t, c, group); len(after) != 0 {
		t.Errorf("still a member after revocation: %+v", after)
	}

	// But the grant itself survives, because revocation truncates the period
	// rather than deleting the row — the audit trail outlives the access.
	rows := seedQuery(t, `SELECT count(*) FROM group_members
	                       WHERE group_id = (SELECT id FROM entities WHERE name = '`+group+`')`)
	if rows == "0" {
		t.Error("revocation deleted the grant; who granted access and why is gone")
	}
}

// TestExpiredGrantIsNotMembership.
//
// The property the temporal model exists for: access that has run out stops
// applying without a job having run.
func TestExpiredGrantIsNotMembership(t *testing.T) {
	c, _ := adminClient(t)

	const (
		login = "e2e-expired"
		group = "e2e-expired-squad"
	)
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', '`+login+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('group', '`+group+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `DELETE FROM group_members
	             WHERE group_id = (SELECT id FROM entities WHERE name = '`+group+`')`)

	// Already over. No sleeping, and nothing had a chance to clean up.
	seedSQL(t, `INSERT INTO group_members (group_id, member_id, granted_by, valid_period, reason)
	            SELECT g.id, u.id, u.id,
	                   tstzrange(now() - interval '2 hours', now() - interval '1 hour'),
	                   'a fortnight that ended'
	              FROM entities g, entities u
	             WHERE g.name = '`+group+`' AND u.name = '`+login+`'`)

	if members := groupMembers(t, c, group); len(members) != 0 {
		t.Errorf("an expired grant still counts as membership: %+v", members)
	}
}

type memberRow struct {
	Member string     `json:"member"`
	Until  *time.Time `json:"until"`
	Reason string     `json:"reason"`
}

func groupMembers(t *testing.T, c *http.Client, group string) []memberRow {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/groups/"+group, "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("reading %s returned %d: %s", group, resp.StatusCode, body)
	}

	var detail struct {
		Members []memberRow `json:"members"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	return detail.Members
}
