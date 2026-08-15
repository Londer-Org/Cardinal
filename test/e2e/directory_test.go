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

// TestTheDirectoryListsEveryTypeAndNotOnlyThoseWithAPage.
//
// `cardinal list` and `show` were the last reading commands to open the
// database, and moving them found the gap this covers: the per-type
// collections exist for the types with a console page, so a service account, a
// device or a role could be created and then listed by nothing. The listing
// answers a different question from those collections — what is in the
// directory, one row each — and it is the only one that can answer it.
func TestTheDirectoryListsEveryTypeAndNotOnlyThoseWithAPage(t *testing.T) {
	c, _ := adminClient(t)

	const role = "e2e-list-role"
	const device = "e2e-list-device"
	createFixture(t, "role", role)
	createFixture(t, "device", device)

	entities := func(query string) map[string]string {
		t.Helper()
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/directory/entities"+query, "application/json")
		defer drain(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("listing%s returned %d", query, resp.StatusCode)
		}
		var body struct {
			Entities []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"entities"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		byName := map[string]string{}
		for _, e := range body.Entities {
			byName[e.Name] = e.Type
		}
		return byName
	}

	all := entities("")
	if all[role] != "role" {
		t.Errorf("a role is absent from the directory listing; it was created and "+
			"nothing but a database client can see it (%q)", all[role])
	}
	if all[device] != "device" {
		t.Errorf("a device is absent from the directory listing (%q)", all[device])
	}

	// Filtering by type narrows rather than being ignored, which would read as
	// an answer about roles that happened to contain everything.
	roles := entities("?type=role")
	if roles[role] != "role" {
		t.Error("filtering by role did not return the role")
	}
	if _, ok := roles[device]; ok {
		t.Error("filtering by role returned a device, so the filter is ignored " +
			"and every answer it gives is about the wrong question")
	}

	// An unknown type is refused, for the same reason: silently returning
	// everything would read as "there are none of those".
	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/entities?type=wombat", "application/json")
	drain(resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("an unknown type returned %d, want 400", resp.StatusCode)
	}
}

// TestShowResolvesMembershipThroughNestedGroups.
//
// The transitive answer is the one that decides anything — policy reads the
// resolved set — so a view that listed only direct grants would disagree with
// every decision made about the account it described.
func TestShowResolvesMembershipThroughNestedGroups(t *testing.T) {
	c, _ := adminClient(t)

	const (
		member = "e2e-nested-member"
		inner  = "e2e-nested-inner"
		outer  = "e2e-nested-outer"
	)
	createFixture(t, "user", member)
	createFixture(t, "group", inner)
	createFixture(t, "group", outer)
	grantFixture(t, inner, member, "nested e2e")
	grantFixture(t, outer, inner, "nested e2e")
	t.Cleanup(func() {
		revokeAfterwards(inner, member)
		revokeAfterwards(outer, inner)
	})

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/entities/user/"+member, "application/json")
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reading the entity returned %d", resp.StatusCode)
	}

	var body struct {
		Memberships []struct {
			Group  string `json:"group"`
			Direct bool   `json:"direct"`
			Depth  int    `json:"depth"`
		} `json:"memberships"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	var sawInner, sawOuter bool
	for _, m := range body.Memberships {
		switch m.Group {
		case inner:
			sawInner = true
			if !m.Direct || m.Depth != 1 {
				t.Errorf("%s is direct=%v depth=%d, want direct at depth 1",
					inner, m.Direct, m.Depth)
			}
		case outer:
			sawOuter = true
			if m.Direct {
				t.Errorf("%s is reported as a direct grant; nobody granted it, it "+
					"arrives through %s, and saying otherwise sends whoever is "+
					"removing this access to the wrong group", outer, inner)
			}
			if m.Depth != 2 {
				t.Errorf("%s is at depth %d, want 2", outer, m.Depth)
			}
		}
	}
	if !sawInner {
		t.Error("the direct membership is missing")
	}
	if !sawOuter {
		t.Error("the inherited membership is missing, so this view disagrees with " +
			"every policy decision made about the account")
	}
}

// TestMailSettingsReportWhetherAPasswordIsStored.
//
// `passwordSet` was computed from the *username*, which is a different field
// answering a different question. A relay configured with a username and no
// password reported that a password was set — sending whoever was debugging a
// refused authentication to look anywhere but at the missing secret.
func TestMailSettingsReportWhetherAPasswordIsStored(t *testing.T) {
	c, csrf := adminClient(t)

	settings := func() (username string, passwordSet bool) {
		t.Helper()
		resp := request(t, c, http.MethodGet, hostCardinal,
			"/api/mail/settings", "application/json")
		defer drain(resp)
		var body struct {
			Username    string `json:"username"`
			PasswordSet bool   `json:"passwordSet"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body.Username, body.PasswordSet
	}

	save := func(body map[string]any) {
		t.Helper()
		resp, err := c.Do(jsonRequest(t, http.MethodPut, "/api/mail/settings", csrf, body))
		if err != nil {
			t.Fatal(err)
		}
		defer drain(resp)
		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			t.Fatalf("saving mail settings returned %d", resp.StatusCode)
		}
	}

	// Put it back afterwards, so an unrelated run does not inherit a relay.
	t.Cleanup(func() {
		saveMailAfterwards(map[string]any{
			"enabled": false, "host": "", "port": 587, "username": "",
			"fromAddress": "", "fromName": "", "replyTo": "", "tlsMode": "starttls",
		})
	})

	// A username and no password. Empty means "leave the stored one alone", and
	// nothing was ever stored, so this is the misreported case.
	save(map[string]any{
		"enabled": false, "host": "relay.invalid", "port": 587,
		"username": "e2e-relay-user", "password": "",
		"fromAddress": "cardinal@cardinal.test", "tlsMode": "starttls",
	})
	if username, set := settings(); set {
		t.Errorf("a relay with username %q and no stored password reports one is "+
			"set; the field answers about the username instead", username)
	}

	// And with one. This is why the stack configures mail.encryption_key: a
	// password cannot be stored at all without it.
	save(map[string]any{
		"enabled": false, "host": "relay.invalid", "port": 587,
		"username": "e2e-relay-user", "password": "e2e-relay-secret",
		"fromAddress": "cardinal@cardinal.test", "tlsMode": "starttls",
	})
	if _, set := settings(); !set {
		t.Error("a stored password is reported as absent, which is the same " +
			"failure in the other direction: it sends somebody to set one that " +
			"is already there")
	}
}

// TestARefusedTestSendIsNotReportedAsSuccess.
//
// The send happens during the request rather than through the outbox, because
// the point is to see the answer — and a relay's refusal comes back as a *200*
// carrying `sent: false` and the relay's own words. A caller reading only the
// status code prints "sent" for a message nobody received.
func TestARefusedTestSendIsNotReportedAsSuccess(t *testing.T) {
	c, csrf := adminClient(t)

	t.Cleanup(func() {
		saveMailAfterwards(map[string]any{
			"enabled": false, "host": "", "port": 587, "username": "",
			"fromAddress": "", "fromName": "", "replyTo": "", "tlsMode": "starttls",
		})
	})

	// A relay that cannot be reached. Nothing in this stack runs one, which is
	// what makes the refusal reliable rather than a race with a real server.
	resp, err := c.Do(jsonRequest(t, http.MethodPut, "/api/mail/settings", csrf,
		map[string]any{
			"enabled": true, "host": "127.0.0.1", "port": 2,
			"fromAddress": "cardinal@cardinal.test", "tlsMode": "none",
		}))
	if err != nil {
		t.Fatal(err)
	}
	drain(resp)

	sent, err := c.Do(jsonRequest(t, http.MethodPost, "/api/mail/test", csrf,
		map[string]string{"to": "nobody@cardinal.test"}))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(sent)

	if sent.StatusCode != http.StatusOK {
		t.Fatalf("a refused send returned %d; it answers 200 and reports the "+
			"refusal in the body, which is the whole trap", sent.StatusCode)
	}
	var body struct {
		Sent  bool   `json:"sent"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(sent.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Sent {
		t.Fatal("a relay that cannot be connected to reported a successful send")
	}
	if body.Error == "" {
		t.Error("no reason given, so whoever ran this knows only that it failed — " +
			"and \"550 user unknown\" and a TLS failure want different responses")
	}
}
