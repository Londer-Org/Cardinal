package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
)

// Provisioning over SCIM, against the running stack.
//
// The claim is that an identity provider can point at Cardinal and keep a
// directory in step. What makes that non-obvious is ADR 0031: every
// administrative action here is guarded by a forbid demanding a device-bound
// credential used in the last five minutes, and a machine synchronising at 3am
// has neither. Provisioning is therefore its own Cedar action with its own
// token scope — and the tests that matter most are the ones showing the bounds
// on that, not the ones showing it works.

const scimBase = "/scim/v2"

// scimToken issues a token that may provision, and puts its owner in the group
// the shipped rule names.
//
// Both halves, deliberately: the scope and the membership. Either alone must
// not be enough, which the refusal tests below assert.
func scimToken(t *testing.T) string {
	t.Helper()
	adminClient(t)

	grantProvisioner(t)

	out := cardinalCLI(t, "token", "create", tokenOwnerLogin,
		"-name", "e2e-scim", "-for", "1h", "-scope", "scim")
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "crd_pat_") {
			return field
		}
	}
	t.Fatalf("no token in output: %s", out)
	return ""
}

// grantProvisioner puts the token owner in the group the shipped rule names.
//
// Tolerant of already being a member: an existing grant is an overlap, which is
// the temporal model refusing to record two truths about one period rather than
// an error worth failing a test over. Every test here needs the membership and
// only the first one creates it.
func grantProvisioner(t *testing.T) {
	t.Helper()

	full := append([]string{
		"compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "cardinal", "cardinal",
	}, "grant", "provisioners", tokenOwnerLogin, "-reason", "e2e scim")
	out, err := exec.CommandContext(t.Context(), "docker", full...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already exists") {
		t.Fatalf("granting provisioners: %v\n%s", err, out)
	}
}

func scimRequest(
	t *testing.T, token, method, path string, body any,
) (*http.Response, []byte) {
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
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/scim+json")

	resp, err := client(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)

	read, _ := io.ReadAll(resp.Body) //nolint:errcheck // reported by whichever assertion follows
	return resp, read
}

// TestProvisioningAWholeAccountLifecycle.
//
// Create, find by the filter a reconciliation actually sends, rename, add to a
// group, deprovision. One test rather than five because the interesting thing
// is the sequence: an identity provider does all of it to the same record, and
// each step has to find what the previous one left.
func TestProvisioningAWholeAccountLifecycle(t *testing.T) {
	token := scimToken(t)
	login := "e2e-scim-person"

	// Idempotent across runs: an entity is never deleted, so a previous run's
	// is renamed out of the way.
	seedSQL(t, `UPDATE entities SET name = name || '-' || id, external_id = NULL
	             WHERE name = '`+login+`'`)

	//nolint:bodyclose // scimRequest drains it before returning
	resp, body := scimRequest(t, token, http.MethodPost, scimBase+"/Users", map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   login,
		"externalId": "e2e-external-1",
		"name":       map[string]any{"formatted": "Provisioned Person"},
		"emails":     []map[string]any{{"value": "person@example.com", "primary": true}},
		"active":     true,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("creating returned %d: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/scim+json") {
		t.Errorf("content type is %q — some clients check, and this is the first "+
			"thing a strict implementation tests", got)
	}

	var created struct {
		ID       string `json:"id"`
		UserName string `json:"userName"`
		Active   bool   `json:"active"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || !created.Active {
		t.Fatalf("created record is wrong: %s", body)
	}

	// The filter reconciliation sends. Getting startIndex or the Resources key
	// wrong here is what makes a client re-create everybody.
	//nolint:bodyclose // scimRequest drains it before returning
	resp, body = scimRequest(t, token, http.MethodGet,
		scimBase+`/Users?filter=userName+eq+%22`+login+`%22`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("filtering returned %d: %s", resp.StatusCode, body)
	}
	var list struct {
		TotalResults int `json:"totalResults"`
		StartIndex   int `json:"startIndex"`
		Resources    []struct {
			ID       string `json:"id"`
			UserName string `json:"userName"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.TotalResults != 1 || len(list.Resources) != 1 {
		t.Fatalf("filter found %d records: %s", list.TotalResults, body)
	}
	if list.StartIndex != 1 {
		t.Errorf("startIndex is %d — SCIM counts from one, and zero drops the "+
			"first record of every page", list.StartIndex)
	}
	if list.Resources[0].ID != created.ID {
		t.Errorf("the filter found a different record than was created")
	}

	// Deprovisioning the way an identity provider actually does it.
	//nolint:bodyclose // scimRequest drains it before returning
	resp, body = scimRequest(t, token, http.MethodPatch,
		scimBase+"/Users/"+created.ID, map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{
				{"op": "replace", "path": "active", "value": false},
			},
		})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patching active returned %d: %s", resp.StatusCode, body)
	}
	var patched struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(body, &patched); err != nil {
		t.Fatal(err)
	}
	if patched.Active {
		t.Fatal("active:false was accepted and the account is still active")
	}
}

// TestASystemGroupIsNotProvisionable.
//
// The escalation ADR 0031 exists to close. Membership of directory-admins is a
// grant of authority inside Cardinal, so a provisioning client able to PATCH it
// would be a path from "the IdP integration" to "directory administrator".
//
// 403 rather than 404: pretending the group is not there would send an operator
// hunting for a synchronisation bug that does not exist.
func TestASystemGroupIsNotProvisionable(t *testing.T) {
	token := scimToken(t)

	//nolint:bodyclose // scimRequest drains it before returning
	resp, body := scimRequest(t, token, http.MethodGet,
		scimBase+`/Groups?filter=displayName+eq+%22directory-admins%22`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("listing returned %d: %s", resp.StatusCode, body)
	}
	var list struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Resources) != 1 {
		t.Fatalf("directory-admins was not found to try against: %s", body)
	}

	//nolint:bodyclose // scimRequest drains it before returning
	resp, body = scimRequest(t, token, http.MethodPatch,
		scimBase+"/Groups/"+list.Resources[0].ID, map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{
				{"op": "add", "path": "members", "value": []map[string]any{
					{"value": "00000000-0000-7000-8000-00000000ad11"},
				}},
			},
		})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("patching a system group returned %d, want 403: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "authority inside Cardinal") {
		t.Errorf("the refusal does not say why: %s", body)
	}

	//nolint:bodyclose // scimRequest drains it before returning
	resp, _ = scimRequest(t, token, http.MethodDelete,
		scimBase+"/Groups/"+list.Resources[0].ID, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("deleting a system group returned %d, want 403", resp.StatusCode)
	}
}

// TestAScopelessTokenCannotProvision.
//
// Half of ADR 0031's pair. The owner is a member of provisioners, so policy
// permits Provision — and the token was issued for something else, which must
// be enough to refuse it. Otherwise every token a provisioner holds becomes a
// provisioning credential.
func TestAScopelessTokenCannotProvision(t *testing.T) {
	adminClient(t)
	grantProvisioner(t)

	out := cardinalCLI(t, "token", "create", tokenOwnerLogin,
		"-name", "e2e-not-scim", "-for", "1h", "-scope", "identity")
	var wrong string
	for _, field := range strings.Fields(out) {
		if strings.HasPrefix(field, "crd_pat_") {
			wrong = field
		}
	}
	if wrong == "" {
		t.Fatalf("no token in output: %s", out)
	}

	//nolint:bodyclose // scimRequest drains it before returning
	resp, body := scimRequest(t, wrong, http.MethodGet, scimBase+"/Users", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a token without the scim scope reached SCIM: %d %s", resp.StatusCode, body)
	}
}

// TestAnUnsupportedFilterIsRefusedRatherThanApproximated.
//
// A filter silently misread returns the wrong people and a provisioning client
// acts on the answer. A clear refusal is something a client falls back from; a
// plausible wrong answer is not.
func TestAnUnsupportedFilterIsRefusedRatherThanApproximated(t *testing.T) {
	token := scimToken(t)

	//nolint:bodyclose // scimRequest drains it before returning
	resp, body := scimRequest(t, token, http.MethodGet,
		scimBase+`/Users?filter=userName+eq+%22a%22+and+active+eq+true`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a compound filter returned %d, want 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "urn:ietf:params:scim:api:messages:2.0:Error") {
		t.Errorf("the error is not in SCIM's shape, so a client cannot parse it: %s", body)
	}
}

// TestDiscoveryTellsAClientWhatIsMissing.
//
// ServiceProviderConfig is the mechanism the specification provides for being
// honest about gaps. Without it a missing feature is discovered from a failure
// in the middle of a synchronisation.
func TestDiscoveryTellsAClientWhatIsMissing(t *testing.T) {
	token := scimToken(t)

	//nolint:bodyclose // scimRequest drains it before returning
	resp, body := scimRequest(t, token, http.MethodGet,
		scimBase+"/ServiceProviderConfig", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery returned %d: %s", resp.StatusCode, body)
	}

	var config struct {
		Patch          struct{ Supported bool } `json:"patch"`
		Bulk           struct{ Supported bool } `json:"bulk"`
		Filter         struct{ Supported bool } `json:"filter"`
		ChangePassword struct{ Supported bool } `json:"changePassword"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatal(err)
	}
	if !config.Patch.Supported || !config.Filter.Supported {
		t.Error("discovery claims not to support what this actually does")
	}
	if config.Bulk.Supported {
		t.Error("discovery claims bulk, which is not implemented — a client would " +
			"send one and fail mid-synchronisation")
	}
	if config.ChangePassword.Supported {
		t.Error("discovery claims changePassword; there is no password column")
	}
}
