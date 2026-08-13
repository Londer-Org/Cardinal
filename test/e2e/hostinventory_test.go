package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
)

// The fleet, as the console shows it.
//
// The question nothing else in Cardinal answers: which machines are still
// checking in. Everything else here — enrolment, certificates, assignments —
// is about one host at a time, and none of it says whether a machine somebody
// set up in March is still being managed.

type inventoryHost struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Enrolled    bool   `json:"enrolled"`
	LastSeen    string `json:"lastSeen"`
	Aliases     int    `json:"aliases"`
	Groups      int    `json:"groups"`
	Disabled    bool   `json:"disabled"`
}

func inventory(t *testing.T, query string) []inventoryHost {
	t.Helper()

	c, _ := adminClient(t)
	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/hosts?q="+query, "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var body struct {
		Items []inventoryHost `json:"items"`
		Total int             `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Items
}

func find(t *testing.T, hosts []inventoryHost, name string) inventoryHost {
	t.Helper()
	for _, h := range hosts {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("%s is not in the inventory: %+v", name, hosts)
	return inventoryHost{}
}

// TestInventoryDistinguishesNeverEnrolledFromSilent.
//
// Three states that look the same in a naive listing and call for completely
// different responses. Never enrolled is a machine nobody set up. Enrolled and
// never seen is one that registered a key and has not come back. A timestamp is
// one that was working — and whether it was working *recently* is the whole
// question.
func TestInventoryDistinguishesNeverEnrolledFromSilent(t *testing.T) {
	tryCardinalCLI(t, "host", "create", "e2e-inv-fresh")

	enrolled := enrolledHost(t, "e2e-inv-seen")
	// enrolledHost signs a request as part of its own check, so this one has
	// authenticated and carries a last-seen.
	_ = enrolled

	hosts := inventory(t, "e2e-inv-")

	fresh := find(t, hosts, "e2e-inv-fresh")
	if fresh.Enrolled {
		t.Fatal("a host that never enrolled is reported as enrolled")
	}
	if fresh.LastSeen != "" {
		t.Fatalf("a host that never enrolled has a last-seen: %q", fresh.LastSeen)
	}

	seen := find(t, hosts, "e2e-inv-seen")
	if !seen.Enrolled {
		t.Fatal("an enrolled host is not reported as enrolled")
	}
	if seen.LastSeen == "" {
		t.Fatal("a host that authenticated has no last-seen")
	}
}

// TestInventoryIncludesDisabledHosts.
//
// Unlike every other listing, and deliberately. A machine somebody cut off is
// exactly what an operator comes to this page looking for, and hiding it would
// answer "no such host" to the question "did we disable that one?".
func TestInventoryIncludesDisabledHosts(t *testing.T) {
	tryCardinalCLI(t, "host", "create", "e2e-inv-off")
	seedSQL(t, `UPDATE entities SET disabled_at = now() WHERE name = 'e2e-inv-off'`)

	off := find(t, inventory(t, "e2e-inv-off"), "e2e-inv-off")
	if !off.Disabled {
		t.Fatal("a disabled host is not marked as such")
	}
}

// TestInventoryCountsAliasesAndGroups.
//
// Aliases because each one is the power to *be* that name, and a machine
// quietly holding several is worth noticing. Groups because a host in none is
// one no policy rule can reach — it resolves nobody and grants nobody, which
// looks exactly like the agent being broken.
func TestInventoryCountsAliasesAndGroups(t *testing.T) {
	tryCardinalCLI(t, "host", "create", "e2e-inv-named")
	tryCardinalCLI(t, "group", "create", "e2e-inv-fleet")
	tryCardinalCLI(t, "host", "alias", "add", "e2e-inv-named", "e2e-inv-alias-one")
	tryCardinalCLI(t, "host", "alias", "add", "e2e-inv-named", "e2e-inv-alias-two")
	grantFixture(t, "e2e-inv-fleet", "e2e-inv-named")

	named := find(t, inventory(t, "e2e-inv-named"), "e2e-inv-named")
	if named.Aliases != 2 {
		t.Fatalf("got %d aliases, want 2", named.Aliases)
	}
	if named.Groups < 1 {
		t.Fatalf("got %d groups, want at least 1", named.Groups)
	}
}

// TestInventoryIsSearchableByAlias.
//
// Somebody looking for git.example.com is looking for whichever machine answers
// to it, and they do not necessarily know its directory name — that is the
// whole reason aliases exist.
func TestInventoryIsSearchableByAlias(t *testing.T) {
	tryCardinalCLI(t, "host", "create", "e2e-inv-searchme")
	tryCardinalCLI(t, "host", "alias", "add", "e2e-inv-searchme", "e2e-inv-findable.example")

	hosts := inventory(t, "e2e-inv-findable")
	if len(hosts) != 1 || hosts[0].Name != "e2e-inv-searchme" {
		t.Fatalf("searching for an alias found %+v", hosts)
	}
}

// TestInventoryNeedsTheDirectoryTier.
//
// The same tier as people and groups. An ordinary account must not be able to
// enumerate the fleet: the list of every machine in an organisation, with which
// are unmanaged, is reconnaissance.
func TestInventoryNeedsTheDirectoryTier(t *testing.T) {
	c := signedInClient(t)

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/hosts", "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403 — an ordinary account enumerated the fleet",
			resp.StatusCode)
	}
}
