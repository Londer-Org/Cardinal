package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// Publishing a policy over the API.
//
// The endpoint the CLI needs before it can stop being a database client
// (ADR 0033). Everything here runs against the stack, because the interesting
// half is what the server refuses rather than what it stores.

type publishBody struct {
	Version     int64  `json:"version"`
	Digest      string `json:"digest"`
	PolicyCount int    `json:"policyCount"`
	Live        bool   `json:"live"`
	Dangling    []struct {
		Policy     string `json:"policy"`
		Kind       string `json:"kind"`
		Identifier string `json:"identifier"`
	} `json:"dangling"`
}

// TestPublishingOverTheAPIStoresAVersionWithoutMakingItLive.
//
// Publish and activate are two verbs, and the reason is that a set nobody
// looked at should not govern every door the moment it is uploaded. So the
// assertion is not only that a version came back — it is that the live one did
// not move.
func TestPublishingOverTheAPIStoresAVersionWithoutMakingItLive(t *testing.T) {
	c, csrf := adminClient(t)

	before := policyVersions(t, c)

	var out publishBody
	resp := postJSON(t, c, "/api/policy/versions", csrf, map[string]any{ //nolint:bodyclose // postJSON closes the body before returning
		"document":    permissivePolicy(),
		"description": "published over the API",
	}, &out)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("publishing returned %d", resp.StatusCode)
	}

	if out.Version <= before.Live {
		t.Errorf("published version %d is not newer than the live one (%d)",
			out.Version, before.Live)
	}
	if out.PolicyCount == 0 {
		t.Error("the published set reports no rules, which no policy this test sends has")
	}
	if out.Digest == "" {
		t.Error("no digest, so nothing can tell two versions apart by content")
	}
	if out.Live {
		t.Error("publishing made the version live, and it was not asked to")
	}

	after := policyVersions(t, c)
	if after.Live != before.Live {
		t.Errorf("the live version moved from %d to %d without anybody activating it",
			before.Live, after.Live)
	}
}

// TestAPolicyThatDoesNotCompileIsNotStored.
//
// A stored version that cannot load is a row whose only purpose is to be a trap
// in the rollback list: it looks like every other entry, and choosing it during
// an incident fails at the worst moment. The CLI compiles before storing, and
// this path has to as well or the two disagree about what publishing means.
func TestAPolicyThatDoesNotCompileIsNotStored(t *testing.T) {
	c, csrf := adminClient(t)

	before := policyVersions(t, c)

	resp := publishRaw(t, c, csrf, map[string]any{
		"document": "permit(principal, action, resource) // no semicolon, no closing",
	})
	if resp != http.StatusBadRequest {
		t.Fatalf("a policy that does not compile returned %d, not 400", resp)
	}

	after := policyVersions(t, c)
	if len(after.Versions) != len(before.Versions) {
		t.Errorf("the version list grew from %d to %d, so something that cannot "+
			"be activated was stored anyway",
			len(before.Versions), len(after.Versions))
	}
}

// TestPublishingReportsWhatThePolicyNamesAndTheDirectoryDoesNot.
//
// The failure this exists to prevent: a rule naming a group nobody created
// never matches, and Cedar being default-deny makes that indistinguishable from
// the rule working. The CLI warns about it, so the API has to report it or the
// warning disappears the moment the command moves.
func TestPublishingReportsWhatThePolicyNamesAndTheDirectoryDoesNot(t *testing.T) {
	c, csrf := adminClient(t)

	var out publishBody
	resp := postJSON(t, c, "/api/policy/versions", csrf, map[string]any{ //nolint:bodyclose // postJSON closes the body before returning
		"document":    permissivePolicy() + danglingRule,
		"description": "names a group that does not exist",
	}, &out)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("publishing returned %d", resp.StatusCode)
	}

	found := false
	for _, ref := range out.Dangling {
		if strings.Contains(ref.Identifier, "nobody-created-this-group") {
			found = true
		}
	}
	if !found {
		t.Errorf("a rule naming a group the directory does not have was published "+
			"with no warning; dangling was %v", out.Dangling)
	}
}

// TestPublishingNeedsTheBroadTier.
//
// Publishing is not activating, and it is still not something to hold by
// virtue of an ordinary account: a published version is one press away from
// governing every door, including who may publish the next one.
func TestPublishingNeedsTheBroadTier(t *testing.T) {
	c, csrf := tokenUser(t, "e2e-publish-outsider",
		"e2e-publish-outsider-with-entropy-0123456789ab")

	if got := publishRaw(t, c, csrf, map[string]any{"document": permissivePolicy()}); got != http.StatusForbidden {
		t.Errorf("an ordinary account published a policy set: got %d, want 403", got)
	}
}

// TestPublishingNeedsTheCSRFToken.
//
// Every mutation does. Worth asserting on this one because it is new, it is
// reachable from a browser, and what it changes is every rule in the system.
func TestPublishingNeedsTheCSRFToken(t *testing.T) {
	c, _ := adminClient(t)

	if got := publishRaw(t, c, "", map[string]any{"document": permissivePolicy()}); got != http.StatusForbidden {
		t.Errorf("publishing without a CSRF token returned %d, want 403", got)
	}
}

// publishRaw returns the status rather than failing on it, because the subject
// of the tests above is what the endpoint refuses.
func publishRaw(t *testing.T, c *http.Client, csrf string, body map[string]any) int {
	t.Helper()

	resp, err := c.Do(jsonRequest(t, http.MethodPost, "/api/policy/versions", csrf, body))
	if err != nil {
		t.Fatal(err)
	}
	defer drain(resp)
	return resp.StatusCode
}

// danglingRule names a group nothing creates, on purpose.
const danglingRule = `
@id("e2e-dangling")
permit(
    principal in Cardinal::Group::"nobody-created-this-group",
    action == Cardinal::Action::"AccessApplication",
    resource
);
`
