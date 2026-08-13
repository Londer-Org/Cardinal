package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	            SELECT g.id, u.id, '00000000-0000-7000-8000-0000000000d1',
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
		body, _ := io.ReadAll(resp.Body) //nolint:errcheck // a body that will not read is reported by the assertion that follows
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

// TestUserDetailAgreesWithTheList.
//
// The detail endpoint left credentials and invitation state at their zero
// values, so it reported "no passkeys, not invited" for an account the list
// showed as invited. Nothing rendered those fields, so nothing noticed — until
// something did, and then it would have contradicted the badge beside it.
func TestUserDetailAgreesWithTheList(t *testing.T) {
	c, csrf := adminClient(t)

	const login = "e2e-detail-check"
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', '`+login+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `DELETE FROM webauthn_credentials
	             WHERE entity_id = (SELECT id FROM entities WHERE name = '`+login+`')`)

	//nolint:bodyclose // postJSON closes the body before returning
	postJSON(t, c, "/api/invitations", csrf, map[string]any{"login": login}, nil)

	inList := false
	listResp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/users", "application/json")
	var users struct {
		Items []struct {
			Login             string `json:"login"`
			InvitationPending bool   `json:"invitationPending"`
		} `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&users); err != nil {
		t.Fatal(err)
	}
	drain(listResp)
	for _, u := range users.Items {
		if u.Login == login {
			inList = u.InvitationPending
		}
	}

	detailResp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/users/"+login, "application/json")
	defer drain(detailResp)
	var detail struct {
		InvitationPending   bool    `json:"invitationPending"`
		InvitationExpiresAt *string `json:"invitationExpiresAt"`
		Credentials         int     `json:"credentials"`
	}
	if err := json.NewDecoder(detailResp.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}

	if !inList {
		t.Fatal("the list did not report the invitation this test just issued")
	}
	if detail.InvitationPending != inList {
		t.Errorf("list says invitationPending=%v, detail says %v — the console "+
			"would show a badge and an action that disagree", inList,
			detail.InvitationPending)
	}
	if detail.InvitationExpiresAt == nil {
		t.Error("no expiry on the detail, so the console cannot say how long is left")
	}
}

// TestReissuingSupersedesTheOldLink.
//
// The answer to "the link went to the wrong person": issue another, and the
// first stops working immediately.
func TestReissuingSupersedesTheOldLink(t *testing.T) {
	c, csrf := adminClient(t)

	const login = "e2e-relink"
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', '`+login+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `DELETE FROM webauthn_credentials
	             WHERE entity_id = (SELECT id FROM entities WHERE name = '`+login+`')`)

	issue := func() string {
		var out struct {
			URL string `json:"url"`
		}
		//nolint:bodyclose // postJSON closes the body before returning
		postJSON(t, c, "/api/invitations", csrf, map[string]any{"login": login}, &out)
		return out.URL[strings.Index(out.URL, "token=")+len("token="):]
	}

	first := issue()
	second := issue()

	resolves := func(token string) int {
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/enroll?token="+url.QueryEscape(token), "application/json")
		defer drain(resp)
		return resp.StatusCode
	}

	if code := resolves(first); code != http.StatusNotFound {
		t.Errorf("the superseded link still resolves (%d) — two working links "+
			"means revoking one is not revoking", code)
	}
	if code := resolves(second); code != http.StatusOK {
		t.Errorf("the replacement link does not resolve (%d)", code)
	}
}

// TestRevokingAtAnInstantTruncatesToThatInstant.
//
// `cardinal revoke -at` has always accepted an instant; until the command moved
// onto the API the endpoint did not, so the flag only worked on the path that
// opened the database. What it means is worth pinning down in both directions,
// because the two are not symmetrical and the asymmetry is not obvious:
//
//   - An instant in the past shortens the membership to have ended then, which
//     is the case it exists for — access actually stopped on Friday and somebody
//     said so on Monday.
//   - An instant in the future schedules the end rather than being refused. The
//     revocation is `DELETE FOR PORTION OF valid_period FROM $at TO 'infinity'`,
//     so the row keeps the portion before $at, and the person stays a member
//     until then. Measured against this stack, not inferred.
func TestRevokingAtAnInstantTruncatesToThatInstant(t *testing.T) {
	c, csrf := adminClient(t)

	const (
		login = "e2e-revoke-at"
		group = "e2e-revoke-at-squad"
	)
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', '`+login+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('group', '`+group+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	seedSQL(t, `DELETE FROM group_members
	             WHERE group_id = (SELECT id FROM entities WHERE name = '`+group+`')`)

	// Starting in the past, so there is something for a past instant to land
	// inside. A grant made now could only be revoked from now on.
	seedSQL(t, `INSERT INTO group_members
	              (group_id, member_id, granted_by, valid_period, reason)
	            SELECT g.id, u.id, '00000000-0000-7000-8000-0000000000d1',
	                   tstzrange(now() - interval '3 hours', 'infinity'),
	                   'started three hours ago'
	              FROM entities g, entities u
	             WHERE g.name = '`+group+`' AND u.name = '`+login+`'`)

	future := time.Now().Add(2 * time.Hour).UTC()
	revoked := requestWithCSRF(t, c, http.MethodDelete,
		"/api/directory/groups/"+group+"/members/"+login+
			"?at="+url.QueryEscape(future.Format(time.RFC3339)), csrf)
	drain(revoked)
	if revoked.StatusCode != http.StatusNoContent {
		t.Fatalf("revoking at a future instant returned %d, want 204", revoked.StatusCode)
	}

	// Still a member: the end was scheduled, not applied.
	if now := groupMembers(t, c, group); len(now) != 1 {
		t.Fatalf("revoking at a future instant ended the membership immediately; "+
			"got %d current members, want 1", len(now))
	}

	// And gone once that instant passes.
	upper := seedQuery(t, `
		SELECT CASE WHEN upper(valid_period) < now() + interval '3 hours'
		            THEN 'ends' ELSE 'open' END
		  FROM group_members
		 WHERE group_id = (SELECT id FROM entities WHERE name = '`+group+`')`)
	if upper != "ends" {
		t.Errorf("the period is %q; revoking at an instant should have closed it "+
			"at that instant rather than leaving it open", upper)
	}

	// Now the case the flag exists for: an instant in the past.
	past := time.Now().Add(-1 * time.Hour).UTC()
	again := requestWithCSRF(t, c, http.MethodDelete,
		"/api/directory/groups/"+group+"/members/"+login+
			"?at="+url.QueryEscape(past.Format(time.RFC3339)), csrf)
	drain(again)
	if again.StatusCode != http.StatusNoContent {
		t.Fatalf("revoking at a past instant returned %d, want 204", again.StatusCode)
	}
	if now := groupMembers(t, c, group); len(now) != 0 {
		t.Errorf("still a member after being revoked as of an hour ago: %+v", now)
	}

	// The two hours they genuinely held it are still recorded.
	held := seedQuery(t, `
		SELECT CASE WHEN valid_period @> (now() - interval '2 hours')
		            THEN 'recorded' ELSE 'lost' END
		  FROM group_members
		 WHERE group_id = (SELECT id FROM entities WHERE name = '`+group+`')`)
	if held != "recorded" {
		t.Errorf("the membership before the revocation instant is %q; back-dating "+
			"a revocation must shorten the period, not erase it", held)
	}
}
