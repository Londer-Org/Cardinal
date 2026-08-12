package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// POSIX numbers over the API.
//
// Assigning a uid was reachable here for a person and nowhere else. Groups had
// no route, nothing listed what had been handed out, and adoption — the
// operation that makes migrating an existing fleet possible — was CLI-only,
// which meant it needed the database credential.

type posixBody struct {
	Name          string     `json:"name"`
	Type          string     `json:"type"`
	Number        int        `json:"number"`
	HomeDirectory string     `json:"homeDirectory"`
	LoginShell    string     `json:"loginShell"`
	FirstServedAt *time.Time `json:"firstServedAt"`
}

// TestAGroupCanBeGivenAGidOverTheAPI.
//
// Groups were unreachable: the only route was keyed on a login. Asking twice
// answers rather than refusing, because a group has one number and it cannot
// change — an idempotent assign is what makes the command safe to re-run.
func TestAGroupCanBeGivenAGidOverTheAPI(t *testing.T) {
	c, csrf := adminClient(t)
	group := "e2e-posix-" + strconv.FormatInt(time.Now().UnixNano()%100000, 10)

	cardinalCLI(t, "group", "create", group)

	var first posixBody
	resp := putJSON(t, c, "/api/directory/groups/"+group+"/posix", csrf, nil, &first)
	if resp != http.StatusCreated {
		t.Fatalf("assigning a gid returned %d, want 201", resp)
	}
	if first.Number == 0 {
		t.Fatal("a gid of zero was handed out, which is root's")
	}
	if first.Type != "group" {
		t.Errorf("the identity came back as %q, not a group", first.Type)
	}
	if first.HomeDirectory != "" || first.LoginShell != "" {
		t.Errorf("a group was given a home directory or a shell: %+v", first)
	}

	var again posixBody
	if status := putJSON(t, c, "/api/directory/groups/"+group+"/posix", csrf, nil, &again); status != http.StatusOK {
		t.Fatalf("asking again returned %d, want 200", status)
	}
	if again.Number != first.Number {
		t.Errorf("the gid changed on a second assign: %d then %d — a number that "+
			"moves is a number that has already been written to a filesystem",
			first.Number, again.Number)
	}
}

// TestTheNumbersHandedOutCanBeListed.
//
// "What is already taken" is the question asked before adopting anything, and
// the per-entity views cannot answer it.
func TestTheNumbersHandedOutCanBeListed(t *testing.T) {
	c, csrf := adminClient(t)
	group := "e2e-posix-list-" + strconv.FormatInt(time.Now().UnixNano()%100000, 10)

	cardinalCLI(t, "group", "create", group)
	var assigned posixBody
	putJSON(t, c, "/api/directory/groups/"+group+"/posix", csrf, nil, &assigned)

	var out struct {
		Identities []posixBody `json:"identities"`
	}
	resp := request(t, c, http.MethodGet, hostCardinal, "/api/posix", "application/json")
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing returned %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}

	for _, id := range out.Identities {
		if id.Name == group {
			if id.Number != assigned.Number {
				t.Errorf("the listing reports %d for %s and the assignment said %d",
					id.Number, group, assigned.Number)
			}
			return
		}
	}
	t.Errorf("a number was handed out to %s and the listing does not have it", group)
}

// TestANumberAMachineAlreadyUsesCanBeAdopted.
//
// The migration operation. A uid that disagrees blocks a cutover, because the
// moment Cardinal wins every file that account owns is reattributed.
func TestANumberAMachineAlreadyUsesCanBeAdopted(t *testing.T) {
	c, csrf := adminClient(t)
	login := "e2e-adopt-" + strconv.FormatInt(time.Now().UnixNano()%100000, 10)

	cardinalCLI(t, "user", "create", login)

	var assigned posixBody
	if status := putJSON(t, c, "/api/directory/users/"+login+"/posix", csrf,
		map[string]any{}, &assigned); status != http.StatusOK && status != http.StatusCreated {
		t.Fatalf("assigning a uid returned %d", status)
	}

	// A number the fleet is presumed to use already, well clear of what the
	// allocator hands out so the two cannot coincide.
	const theirs = 4242

	var adopted posixBody
	if status := postJSONStatus(t, c, "/api/directory/users/"+login+"/posix/adopt", csrf,
		map[string]any{"number": theirs}, &adopted); status != http.StatusOK {
		t.Fatalf("adopting returned %d, want 200", status)
	}
	if adopted.Number != theirs {
		t.Errorf("adopted %d and the identity reports %d", theirs, adopted.Number)
	}
	if assigned.Number == adopted.Number {
		t.Error("the number did not change, so nothing was adopted")
	}

	// Read back independently: a handler that echoes its input without writing
	// would satisfy everything above.
	out := cardinalCLI(t, "posix", "show", "user", login)
	if !strings.Contains(out, strconv.Itoa(theirs)) {
		t.Errorf("the directory does not report %d for %s after adoption:\n%s",
			theirs, login, out)
	}
}

// TestAReservedNumberIsRefusedWithAReason.
//
// Zero is root's. A migration tool that accepts it produces an account the
// system treats as the superuser on every host it reaches.
//
// Asserting the *reason* and not merely a non-200, which is the version this
// test had first and which proved nothing: the schema carries its own CHECK, so
// removing the application's refusal still failed the request — as a 500 from a
// constraint violation. That satisfies "not 200" while losing the sentence that
// tells an operator what to do, and it means the guard could be deleted without
// a single test noticing.
func TestAReservedNumberIsRefusedWithAReason(t *testing.T) {
	c, csrf := adminClient(t)
	login := "e2e-adopt-reserved-" + strconv.FormatInt(time.Now().UnixNano()%100000, 10)

	cardinalCLI(t, "user", "create", login)
	putJSON(t, c, "/api/directory/users/"+login+"/posix", csrf, map[string]any{}, nil)

	for _, number := range []int{0, 1, 999, 61500} {
		status, body := postJSONBody(t, c, "/api/directory/users/"+login+"/posix/adopt", csrf,
			map[string]any{"number": number})
		if status != http.StatusConflict {
			t.Errorf("adopting %d returned %d, want 409: %s", number, status, body)
			continue
		}
		if !strings.Contains(body, strconv.Itoa(number)) {
			t.Errorf("the refusal of %d does not name the number, so it cannot say "+
				"what to do next: %s", number, body)
		}
	}
}

// TestAdoptingNeedsTheAdministrativeTier.
//
// Changing which number an account owns changes who owns files on every host
// that account reaches.
func TestAdoptingNeedsTheAdministrativeTier(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-posix-outsider",
		"e2e-posix-outsider-with-entropy-0123456789ab")

	status := postJSONStatus(t, c, "/api/directory/users/e2e-user/posix/adopt", csrf,
		map[string]any{"number": 5555}, nil)
	if status != http.StatusForbidden {
		t.Errorf("an ordinary account adopted a POSIX number: got %d, want 403", status)
	}
}

// postJSONBody returns the status and the raw body, because several of these
// assert on the sentence a refusal carries.
func postJSONBody(t *testing.T, c *http.Client, path, csrf string, body map[string]any) (int, string) {
	t.Helper()

	resp, err := c.Do(jsonRequest(t, http.MethodPost, path, csrf, body))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

func putJSON(t *testing.T, c *http.Client, path, csrf string, body, out any) int {
	t.Helper()
	return sendJSON(t, c, http.MethodPut, path, csrf, body, out)
}

func postJSONStatus(t *testing.T, c *http.Client, path, csrf string, body, out any) int {
	t.Helper()
	return sendJSON(t, c, http.MethodPost, path, csrf, body, out)
}

// sendJSON returns the status rather than failing on it: several tests here
// are about what the endpoint refuses.
func sendJSON(t *testing.T, c *http.Client, method, path, csrf string, body, out any) int {
	t.Helper()

	resp, err := c.Do(jsonRequest(t, method, path, csrf, body))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decoding %s %s: %v", method, path, err)
		}
	}
	return resp.StatusCode
}
