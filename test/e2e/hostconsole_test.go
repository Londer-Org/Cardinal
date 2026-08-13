package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// Hosts from the console.
//
// All of this existed as a CLI command and nowhere else, so the inventory page
// was a list of machines you could look at and not touch: adding a host,
// handing it a way in, granting it another name it may prove, all needed a
// shell on the Cardinal server and a database connection string.

type hostDetailBody struct {
	Name        string   `json:"name"`
	Enrolled    bool     `json:"enrolled"`
	AliasNames  []string `json:"aliasNames"`
	Credentials []struct {
		Fingerprint string `json:"fingerprint"`
		Live        bool   `json:"live"`
	} `json:"credentials"`
	Access []struct {
		Login        string `json:"login"`
		LocalAccount string `json:"localAccount"`
		UID          int    `json:"uid"`
		Sudo         bool   `json:"sudo"`
	} `json:"access"`
	AccessUnavailable bool `json:"accessUnavailable"`
}

func (h hostDetailBody) logins() []string {
	out := make([]string, 0, len(h.Access))
	for _, a := range h.Access {
		out = append(out, a.LocalAccount)
	}
	slices.Sort(out)
	return out
}

// jsonRequest builds a mutating request, body optional.
//
// Not postJSON: that helper calls t.Fatal on anything that is not a success,
// which is right for the paths that must work and useless here, where half the
// assertions are about what gets turned away.
func jsonRequest(t *testing.T, method, path, csrf string, body any) *http.Request {
	t.Helper()

	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, origin(hostCardinal)+path, payload) //nolint:noctx // bounded by client timeout
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Cardinal-CSRF", csrf)
	return req
}

func hostDetail(t *testing.T, c *http.Client, name string) hostDetailBody {
	t.Helper()

	resp := request(t, c, http.MethodGet, hostCardinal,
		"/api/directory/hosts/"+name, "application/json")
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("host detail returned %d", resp.StatusCode)
	}

	var out hostDetailBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTheConsoleAgreesWithTheMachine.
//
// The test that makes the "who can log in" panel worth having. Two independent
// paths to the same answer: /api/hosts/assignment, which the agent authenticates
// to with its own key and installs the result of, and the console's host page,
// which an administrator reads.
//
// They must not drift. A console that disagreed with the sudoers file would be
// worse than no console, because somebody would trust it — and they would only
// find out during an incident, comparing a screen against a machine.
//
// Compared rather than asserted against a fixed list on purpose: the point is
// that two code paths agree, not that either matches something written here.
func TestTheConsoleAgreesWithTheMachine(t *testing.T) {
	defer hostAccessFixture(t)()

	const host = "e2e-console-agrees.prod"
	identity := enrolledHostInGroup(t, host)

	fromMachine := fetchAssignment(t, identity)
	admin, _ := adminClient(t)
	fromConsole := hostDetail(t, admin, host)

	if fromConsole.AccessUnavailable {
		t.Fatal("the console could not work out access while the machine could")
	}

	if got, want := fromConsole.logins(), fromMachine.names(); !slices.Equal(got, want) {
		t.Fatalf("the console says %v may log in, the machine is told %v", got, want)
	}
	if len(fromMachine.Users) == 0 {
		t.Fatal("the fixture granted nobody — both sides agreeing on nothing " +
			"proves nothing")
	}

	// And sudo, which is the row somebody is actually checking.
	for _, entry := range fromConsole.Access {
		onMachine, ok := fromMachine.user(entry.LocalAccount)
		if !ok {
			t.Fatalf("%s is on the console and not on the machine", entry.LocalAccount)
		}
		if entry.Sudo != onMachine.Sudo {
			t.Errorf("%s: console says sudo=%v, the machine is told %v",
				entry.LocalAccount, entry.Sudo, onMachine.Sudo)
		}
		if entry.UID != onMachine.UID {
			t.Errorf("%s: console says uid %d, the machine is told %d",
				entry.LocalAccount, entry.UID, onMachine.UID)
		}
	}
}

// TestTheConsoleCanAnswerBeforeAHostHasEverEnrolled.
//
// Which is when somebody most wants to check. The machine cannot ask its own
// question yet — it has no key — so if this needed an enrolled host it would be
// unavailable exactly when it is useful.
func TestTheConsoleCanAnswerBeforeAHostHasEverEnrolled(t *testing.T) {
	defer hostAccessFixture(t)()

	const host = "e2e-never-enrolled.prod"
	createFixture(t, "host", host)
	grantFixture(t, "e2e-linux-hosts", host)

	admin, _ := adminClient(t)
	detail := hostDetail(t, admin, host)

	if detail.Enrolled {
		t.Fatal("the fixture host reported itself enrolled")
	}
	if detail.AccessUnavailable {
		t.Fatal("access was unavailable for a host that has not enrolled")
	}
	if len(detail.Access) == 0 {
		t.Fatal("nobody may log in, but the fixture policy grants a group this " +
			"host is in — the answer does not depend on enrollment")
	}
}

// TestAnEnrollmentTokenFromTheConsoleActuallyEnrols.
//
// The console returns a command rather than a token, and the value inside it
// has to work. A dialog that produced a plausible-looking string nobody could
// use would pass every test that only checked for a 201.
func TestAnEnrollmentTokenFromTheConsoleActuallyEnrols(t *testing.T) {
	const host = "e2e-console-enrol.prod"
	createFixture(t, "host", host)

	admin, csrf := adminClient(t)

	var issued struct {
		Command   string `json:"command"`
		ExpiresAt string `json:"expiresAt"`
	}
	resp := postJSON(t, admin, "/api/directory/hosts/"+host+"/enrollment", csrf, nil, &issued) //nolint:bodyclose // the helper drains and closes it; bodyclose cannot see through the call
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("issuing enrollment returned %d", resp.StatusCode)
	}

	// The token is inside the command, which is the whole point of returning a
	// command: an operator holding a bare secret still has to know what to do
	// with it, and the step they get wrong is generating the keypair somewhere
	// other than on the machine.
	var token string
	fields := strings.Fields(issued.Command)
	for i, field := range fields {
		if field == "--token" && i+1 < len(fields) {
			token = fields[i+1]
		}
	}
	if token == "" {
		t.Fatalf("no token in %q", issued.Command)
	}
	if !strings.Contains(issued.Command, "cardinal-agent join") {
		t.Errorf("the command does not run the agent: %q", issued.Command)
	}

	// Redeem it the way a machine does.
	if identity := redeemEnrollment(t, token); identity == nil {
		t.Fatal("the token issued by the console did not enrol the host")
	}

	detail := hostDetail(t, admin, host)
	if !detail.Enrolled {
		t.Fatal("the host is not reported enrolled after using the console's token")
	}
	if len(detail.Credentials) == 0 || !detail.Credentials[0].Live {
		t.Fatalf("no live credential after enrolment: %+v", detail.Credentials)
	}
}

// TestAliasesFromTheConsole.
//
// An alias is the power to *be* that name to anything trusting the authority,
// so the interesting assertion is the refusal: a name another host already
// holds must not be grantable, or two machines could each prove they are the
// same service.
func TestAliasesFromTheConsole(t *testing.T) {
	const first = "e2e-alias-one.prod"
	const second = "e2e-alias-two.prod"
	createFixture(t, "host", first)
	createFixture(t, "host", second)

	admin, csrf := adminClient(t)

	const shared = "e2e-shared-name.example.com"

	// The stack outlives a run, and this test deliberately moves a name between
	// two hosts — so a second run would start with it already held and the first
	// assertion would fail for a reason that has nothing to do with the code.
	seedSQL(t, `DELETE FROM host_aliases WHERE name = '`+shared+`'`)

	add := func(host, alias string) int {
		t.Helper()
		req := jsonRequest(t, http.MethodPost,
			"/api/directory/hosts/"+host+"/aliases", csrf,
			map[string]string{"alias": alias})
		resp, err := admin.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer drain(resp)
		return resp.StatusCode
	}

	if code := add(first, shared); code != http.StatusNoContent {
		t.Fatalf("granting an alias returned %d, want 204", code)
	}
	if !slices.Contains(hostDetail(t, admin, first).AliasNames, shared) {
		t.Fatal("the alias is not listed on the host that holds it")
	}

	if code := add(second, shared); code == http.StatusNoContent {
		t.Fatal("two hosts were both granted the same name — either could then " +
			"prove it is the other")
	}

	// And removing it gives the name back.
	req := jsonRequest(t, http.MethodDelete,
		"/api/directory/hosts/"+first+"/aliases/"+shared, csrf, nil)
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	drain(resp)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("removing an alias returned %d", resp.StatusCode)
	}
	if slices.Contains(hostDetail(t, admin, first).AliasNames, shared) {
		t.Fatal("the alias survived removal")
	}
	if code := add(second, shared); code != http.StatusNoContent {
		t.Fatalf("the freed name could not be granted to another host: %d", code)
	}
}

// TestHostManagementNeedsTheDirectoryTier.
//
// An ordinary account must not be able to add a machine, hand it a way in, or
// grant it a name. The last is the one worth spelling out: an alias lets a
// machine prove it is some other name, so somebody who could grant one could
// stand up a host that impersonates a service.
func TestHostManagementNeedsTheDirectoryTier(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-host-outsider",
		"e2e-host-outsider-with-entropy-0123456789abcdef")

	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/directory/hosts/e2e-alias-one.prod", nil},
		{http.MethodPost, "/api/directory/hosts", map[string]string{"name": "sneaky.prod"}},
		{http.MethodPost, "/api/directory/hosts/e2e-alias-one.prod/enrollment", nil},
		{
			http.MethodPost, "/api/directory/hosts/e2e-alias-one.prod/aliases",
			map[string]string{"alias": "bank.example.com"},
		},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp, err := c.Do(jsonRequest(t, tc.method, tc.path, csrf, tc.body))
			if err != nil {
				t.Fatal(err)
			}
			defer drain(resp)

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("got %d, want 403 — an ordinary account reached host "+
					"management", resp.StatusCode)
			}
		})
	}
}
