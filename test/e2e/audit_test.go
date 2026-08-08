package e2e

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

// The audit journal, through the API a console reads.
//
// Distinct from the decision explorer: that answers "why was I denied" from the
// decision log, and this answers "what happened". It had no reader at all —
// `cardinal audit verify` could say the chain was intact and nothing could say
// what was in it, so the one record that cannot be altered was also the one
// nobody could consult.
//
// Tamper detection is deliberately not re-tested here. internal/store proves it
// against a real PostgreSQL by editing a row directly, which is both a stronger
// test and a safe one; doing it against the shared stack would leave a
// permanently broken journal behind, since the whole point is that the damage
// cannot be undone.

type auditParty struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Redacted bool   `json:"redacted"`
}

type auditEntry struct {
	Seq     int64       `json:"seq"`
	Action  string      `json:"action"`
	Subject *auditParty `json:"subject"`
	Actor   *auditParty `json:"actor"`
}

type auditPage struct {
	Events []auditEntry `json:"events"`
	Before int64        `json:"before"`
}

func auditEvents(t *testing.T, c *http.Client, query string) auditPage {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/audit/events"+query, "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing the journal returned %d", resp.StatusCode)
	}

	var out auditPage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTheJournalResolvesIdentifiersToNames.
//
// The journal stores opaque identifiers and nothing else, which is the point:
// it is the one place erasure cannot reach (ADR 0010), so it holds nothing that
// would ever need erasing. That makes it unreadable on its own — a page of
// UUIDs — and the viewer's job is to resolve them at read time.
func TestTheJournalResolvesIdentifiersToNames(t *testing.T) {
	const login = "e2e-audit-subject"
	tryCardinalCLI(t, "user", "create", login)

	admin, _ := adminClient(t)
	page := auditEvents(t, admin, "?limit=200")

	if len(page.Events) == 0 {
		t.Fatal("the journal is empty, which cannot be true — an entry is " +
			"appended in the same transaction as every change")
	}

	named := 0
	for _, e := range page.Events {
		if e.Subject != nil && e.Subject.Name != "" {
			named++
			if e.Subject.ID == e.Subject.Name {
				t.Fatalf("entry %d resolved a name to its own id — nothing was "+
					"looked up", e.Seq)
			}
		}
	}
	if named == 0 {
		t.Fatal("no entry resolved a subject to a name — the viewer would show " +
			"a page of UUIDs")
	}
}

// TestTheActionFilterActuallyFilters.
//
// A filter that quietly ignores its input looks identical to a journal with
// nothing else in it.
func TestTheActionFilterActuallyFilters(t *testing.T) {
	admin, _ := adminClient(t)

	// Something that certainly happened: adminClient seeds an account, and
	// creating one appends entity.created.
	filtered := auditEvents(t, admin, "?action=entity.created&limit=50")
	if len(filtered.Events) == 0 {
		t.Fatal("no entity.created entries, but accounts have been created")
	}
	for _, e := range filtered.Events {
		if e.Action != "entity.created" {
			t.Fatalf("filtered on entity.created and got %q", e.Action)
		}
	}

	// And the filter is narrowing rather than being ignored: the unfiltered
	// journal contains actions this page does not.
	all := auditEvents(t, admin, "?limit=50")
	others := 0
	for _, e := range all.Events {
		if e.Action != "entity.created" {
			others++
		}
	}
	if others == 0 {
		t.Skip("every recent entry happens to be entity.created, so this cannot " +
			"distinguish a working filter from an ignored one")
	}
}

// TestPagingByCursorNeitherSkipsNorRepeats.
//
// The journal only ever gains rows, at one end. An OFFSET into it shifts every
// time something is appended — so a second page fetched a moment later would
// repeat entries the first page already showed, and skip others entirely.
// Paging by sequence cannot do that, and this is what says so.
func TestPagingByCursorNeitherSkipsNorRepeats(t *testing.T) {
	admin, _ := adminClient(t)

	first := auditEvents(t, admin, "?limit=5")
	if len(first.Events) < 5 || first.Before == 0 {
		t.Skip("fewer than two pages of journal to page through")
	}

	// Append something between the two reads. With an offset this is exactly
	// what shifts the window and duplicates a row.
	tryCardinalCLI(t, "user", "create", "e2e-audit-interleaved")

	second := auditEvents(t, admin, "?limit=5&before="+strconv.FormatInt(first.Before, 10))
	if len(second.Events) == 0 {
		t.Fatal("the second page is empty despite a cursor being offered")
	}

	seen := make(map[int64]bool, len(first.Events))
	for _, e := range first.Events {
		seen[e.Seq] = true
	}
	for _, e := range second.Events {
		if seen[e.Seq] {
			t.Fatalf("entry %d appears on both pages", e.Seq)
		}
		if e.Seq >= first.Before {
			t.Fatalf("entry %d is not older than the cursor %d", e.Seq, first.Before)
		}
	}
}

// TestVerifyingTheChainFromTheConsole.
//
// The thing that makes this a journal rather than a log. A PostgreSQL restore
// tells you the data came back; this tells you nobody altered it.
func TestVerifyingTheChainFromTheConsole(t *testing.T) {
	admin, csrf := adminClient(t)

	var report struct {
		Valid         bool   `json:"valid"`
		EventsChecked int64  `json:"eventsChecked"`
		BrokenAtSeq   int64  `json:"brokenAtSeq"`
		Reason        string `json:"reason"`
	}
	resp := postJSON(t, admin, "/api/audit/verify", csrf, nil, &report) //nolint:bodyclose // the helper drains and closes it; bodyclose cannot see through the call
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verifying returned %d", resp.StatusCode)
	}

	if !report.Valid {
		t.Fatalf("the chain is broken at %d: %s — this is a security incident, "+
			"not a failing test", report.BrokenAtSeq, report.Reason)
	}
	if report.EventsChecked == 0 {
		t.Fatal("nothing was checked, so 'valid' means nothing")
	}
}

// TestAnErasedAccountIsShownAsErased.
//
// Redaction replaces an entity's name with a tombstone and leaves the journal
// untouched — deliberately, since the journal is the one record erasure cannot
// reach. The viewer must say so rather than rendering "redacted-1a2b3c4d" as
// though somebody had chosen it.
func TestAnErasedAccountIsShownAsErased(t *testing.T) {
	const login = "e2e-audit-erased"
	tryCardinalCLI(t, "user", "create", login)

	subject := seedQuery(t,
		`SELECT id FROM entities WHERE type = 'user' AND name = '`+login+`'`)
	if subject == "" {
		t.Fatal("the fixture account was not created")
	}

	admin, _ := adminClient(t)

	// Its entries resolve to a name first, so the change below is attributable
	// to the erasure rather than to the name never having been there.
	before := auditEvents(t, admin, "?subject="+subject+"&limit=20")
	if len(before.Events) == 0 {
		t.Fatal("no journal entries for the fixture account")
	}
	named := false
	for _, e := range before.Events {
		if e.Subject != nil && e.Subject.Name == login {
			named = true
		}
	}
	if !named {
		t.Fatalf("no entry named %q before erasure", login)
	}

	tryCardinalCLI(t, "redact", "user", login, "-yes")

	after := auditEvents(t, admin, "?subject="+subject+"&limit=20")

	// Every entry that existed still exists, unchanged.
	//
	// Not "the count is the same": erasure appends an entity.redacted entry of
	// its own, about the same subject, so the journal legitimately grows. The
	// claim worth checking is that nothing was removed — which is what
	// append-only means, and what makes the record survive the erasure it
	// records.
	surviving := make(map[int64]bool, len(after.Events))
	for _, e := range after.Events {
		surviving[e.Seq] = true
	}
	for _, e := range before.Events {
		if !surviving[e.Seq] {
			t.Fatalf("entry %d vanished when the account was erased — the journal "+
				"is append-only and is the one record erasure cannot reach", e.Seq)
		}
	}
	if len(after.Events) <= len(before.Events) {
		t.Errorf("erasure appended nothing: %d entries before, %d after — the "+
			"erasure itself is an event and belongs in the record",
			len(before.Events), len(after.Events))
	}
	for _, e := range after.Events {
		if e.Subject == nil {
			continue
		}
		if !e.Subject.Redacted {
			t.Fatalf("entry %d still names %q after erasure", e.Seq, e.Subject.Name)
		}
	}
}

// TestTheJournalNeedsTheBroadTier.
//
// It is the record of everything anybody did, including who read it. Not
// something to hold by virtue of managing accounts.
func TestTheJournalNeedsTheBroadTier(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-audit-outsider",
		"e2e-audit-outsider-with-entropy-0123456789abc")

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/audit/events"},
		{http.MethodPost, "/api/audit/verify"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp, err := c.Do(jsonRequest(t, tc.method, tc.path, csrf, nil))
			if err != nil {
				t.Fatal(err)
			}
			defer drain(resp)

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("got %d, want 403", resp.StatusCode)
			}
		})
	}
}
