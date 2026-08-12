package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// Asking the directory about an instant that is not now.
//
// The distinctive property of the data model, and until now it was reachable
// only from the CLI — which is to say only from a shell holding the database
// credential. These drive it over the API, through a grant that is made,
// revoked, and then asked about on both sides of the revocation.

type groupAtBody struct {
	Name    string `json:"name"`
	At      string `json:"at"`
	Members []struct {
		Member string `json:"member"`
		Reason string `json:"reason"`
	} `json:"members"`
}

type historyBody struct {
	Group    string `json:"group"`
	Member   string `json:"member"`
	At       string `json:"at"`
	MemberAt *bool  `json:"memberAt"`
	Grants   []struct {
		From    time.Time  `json:"from"`
		Until   *time.Time `json:"until"`
		Reason  string     `json:"reason"`
		Current bool       `json:"current"`
	} `json:"grants"`
}

// TestTheDirectoryAnswersForAnInstantThatIsNotNow.
//
// One grant, revoked. Afterwards the group is empty *now* and still has the
// member *then*, which is the whole claim of the temporal model and the thing
// an auditor asks about.
func TestTheDirectoryAnswersForAnInstantThatIsNotNow(t *testing.T) {
	c, _ := adminClient(t)
	const group = "e2e-pit"

	cardinalCLI(t, "group", "create", group)
	t.Cleanup(func() { cliBackground("revoke", group, "e2e-user") })

	tryCardinalCLI(t, "grant", group, "e2e-user", "-reason", "point-in-time e2e")

	// Sampled after the grant lands rather than before it, so the instant is
	// unambiguously inside the period rather than on its boundary.
	time.Sleep(time.Second)
	during := time.Now().UTC()

	before := groupAt(t, c, group, "")
	if len(before.Members) != 1 {
		t.Fatalf("expected one member before revoking, got %d", len(before.Members))
	}

	cardinalCLI(t, "revoke", group, "e2e-user")

	now := groupAt(t, c, group, "")
	if len(now.Members) != 0 {
		t.Errorf("the group still reports %d member(s) after revoking", len(now.Members))
	}
	if now.At != "" {
		t.Errorf("a query with no instant echoed one: %q", now.At)
	}

	then := groupAt(t, c, group, during.Format(time.RFC3339))
	if len(then.Members) != 1 {
		t.Errorf("the group reports %d member(s) at %s, when it had one — "+
			"revoking appears to have erased the past rather than closed the period",
			len(then.Members), during.Format(time.RFC3339))
	}
	if then.At == "" {
		t.Error("a query for an instant did not echo it, so an answer about March " +
			"is indistinguishable from an answer about now")
	}
}

// TestHistoryKeepsWhatARevocationClosed.
//
// A revoked grant keeps its row and its reason. That is what makes "why did
// this person have that, and when" answerable, and it is invisible from the
// members list, which by then shows nothing.
func TestHistoryKeepsWhatARevocationClosed(t *testing.T) {
	c, _ := adminClient(t)
	const group = "e2e-pit-history"

	cardinalCLI(t, "group", "create", group)
	t.Cleanup(func() { cliBackground("revoke", group, "e2e-user") })

	tryCardinalCLI(t, "grant", group, "e2e-user", "-reason", "kept after revocation")
	time.Sleep(time.Second)
	during := time.Now().UTC()
	cardinalCLI(t, "revoke", group, "e2e-user")

	history := grantHistory(t, c, group, "e2e-user", during.Format(time.RFC3339))

	if len(history.Grants) == 0 {
		t.Fatal("no grants in the history of a membership that was granted and revoked")
	}
	found := false
	for _, g := range history.Grants {
		if g.Reason == "kept after revocation" {
			found = true
			if g.Until == nil {
				t.Error("the revoked grant has no end, so the revocation did not close it")
			}
			if g.Current {
				t.Error("a revoked grant is reported as current")
			}
		}
	}
	if !found {
		t.Errorf("the reason recorded at grant time did not survive the revocation; got %+v",
			history.Grants)
	}

	if history.MemberAt == nil {
		t.Fatal("history was asked about an instant and did not answer for it")
	}
	if !*history.MemberAt {
		t.Errorf("history says they were not in %s at %s, and they were",
			group, during.Format(time.RFC3339))
	}
}

// TestAMistypedInstantIsRefused.
//
// Ignoring it would answer a different question than the one asked, and look
// like it worked. For an audit query that is the worst of both.
func TestAMistypedInstantIsRefused(t *testing.T) {
	c, _ := adminClient(t)

	for _, raw := range []string{"yesterday", "2026-03-14", "1743000000"} {
		resp, err := c.Do(jsonRequest(t, http.MethodGet,
			"/api/directory/groups/engineers?at="+url.QueryEscape(raw), "", nil))
		if err != nil {
			t.Fatal(err)
		}
		status := resp.StatusCode
		drain(resp)
		if status != http.StatusBadRequest {
			t.Errorf("at=%q returned %d, want 400 — a mistyped instant that means "+
				"\"now\" answers a different question and looks like it worked", raw, status)
		}
	}
}

func groupAt(t *testing.T, c *http.Client, group, at string) groupAtBody {
	t.Helper()

	path := "/api/directory/groups/" + group
	if at != "" {
		path += "?at=" + url.QueryEscape(at)
	}
	var out groupAtBody
	resp := request(t, c, http.MethodGet, hostCardinal, path, "application/json")
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func grantHistory(t *testing.T, c *http.Client, group, member, at string) historyBody {
	t.Helper()

	path := "/api/directory/groups/" + group + "/members/" + member + "/history"
	if at != "" {
		path += "?at=" + url.QueryEscape(at)
	}
	var out historyBody
	resp := request(t, c, http.MethodGet, hostCardinal, path, "application/json")
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
