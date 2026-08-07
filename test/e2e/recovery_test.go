package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Dual-control recovery, and the escalation it closes.
//
// Issuing an enrollment invitation for an account that already has passkeys is
// account takeover by shape. Until this existed, one user-admin could do it to a
// directory-admin — which made the tiers decorative, because the narrow one
// contained a path to the broad one.

// TestUserAdminCannotTakeOverAnAdministrator is the regression test for that.
func TestUserAdminCannotTakeOverAnAdministrator(t *testing.T) {
	adminClient(t)
	giveCredential(t, "e2e-admin")

	c, csrf := tieredClient(t, "e2e-user-admin", adminGroupUserAdmins)

	resp := postRaw(t, c, csrf, "/api/invitations", `{"login":"e2e-admin"}`)
	defer drain(resp)
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 400 {
		t.Fatalf("a user-admin minted an enrollment link for a directory-admin "+
			"(%d): %s — open it, register a passkey, and you are that "+
			"administrator", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "two administrators") {
		t.Errorf("the refusal does not say what to do instead: %s", body)
	}
}

// TestOnboardingStaysSingleControl.
//
// The split must not make ordinary onboarding need two people. An account with
// no credentials cannot be signed in to, so there is nothing to take over.
func TestOnboardingStaysSingleControl(t *testing.T) {
	c, csrf := tieredClient(t, "e2e-user-admin", adminGroupUserAdmins)

	const login = "e2e-fresh-hire"
	seedSQL(t, `DELETE FROM webauthn_credentials
	             WHERE entity_id = (SELECT id FROM entities WHERE name = '`+login+`')`)
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', '`+login+`')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)

	resp := postRaw(t, c, csrf, "/api/invitations", `{"login":"`+login+`"}`)
	defer drain(resp)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("onboarding a fresh account was refused (%d): %s — requiring two "+
			"people to add a colleague is how a control gets removed",
			resp.StatusCode, body)
	}
}

// TestRecoveryNeedsTwoDistinctAdministrators is the property the whole feature
// rests on.
func TestRecoveryNeedsTwoDistinctAdministrators(t *testing.T) {
	first, firstCSRF := adminClient(t)
	seedSQL(t, `INSERT INTO entities (type, name) VALUES ('user', 'e2e-locked-out')
	            ON CONFLICT (type, name) DO UPDATE SET disabled_at = NULL`)
	giveCredential(t, "e2e-locked-out")
	seedSQL(t, `DELETE FROM recovery_requests
	             WHERE subject_id = (SELECT id FROM entities WHERE name = 'e2e-locked-out')`)

	// A second administrator, so there is somebody to be the second person.
	second, secondCSRF := tieredClient(t, "e2e-admin-two", adminGroupDirectoryAdmins)

	t.Run("the request records the requester's approval", func(t *testing.T) {
		resp := postRaw(t, first, firstCSRF, "/api/recoveries",
			`{"login":"e2e-locked-out","reason":"lost both keys"}`)
		defer drain(resp)
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("opening a request returned %d: %s", resp.StatusCode, body)
		}
		var opened struct {
			Approvers []string `json:"approvers"`
			Satisfied bool     `json:"satisfied"`
			Required  int      `json:"required"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&opened); err != nil {
			t.Fatal(err)
		}
		if len(opened.Approvers) != 1 {
			t.Errorf("approvers = %v, want just the requester", opened.Approvers)
		}
		if opened.Satisfied {
			t.Fatal("one administrator satisfied a dual-control request")
		}
		if opened.Required != 2 {
			t.Errorf("required = %d, want 2", opened.Required)
		}
	})

	t.Run("the requester cannot approve twice", func(t *testing.T) {
		resp := postRaw(t, first, firstCSRF,
			"/api/recoveries/e2e-locked-out/approve", "")
		defer drain(resp)
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("the requester approved again (%d) — dual control needs a "+
				"second person, not a second click", resp.StatusCode)
		}
	})

	t.Run("a second administrator completes it", func(t *testing.T) {
		resp := postRaw(t, second, secondCSRF,
			"/api/recoveries/e2e-locked-out/approve", "")
		defer drain(resp)
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("the second approval returned %d: %s", resp.StatusCode, body)
		}

		var approved struct {
			Satisfied     bool     `json:"satisfied"`
			Approvers     []string `json:"approvers"`
			InvitationURL string   `json:"invitationUrl"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&approved); err != nil {
			t.Fatal(err)
		}
		if !approved.Satisfied {
			t.Fatal("two administrators did not satisfy the threshold")
		}
		if len(approved.Approvers) != 2 {
			t.Errorf("approvers = %v, want two distinct people", approved.Approvers)
		}
		if !strings.Contains(approved.InvitationURL, "/enroll?token=") {
			t.Fatalf("no enrollment link was issued: %q", approved.InvitationURL)
		}

		// And the link works, unauthenticated.
		token := approved.InvitationURL[strings.Index(approved.InvitationURL, "token=")+6:]
		anon := client(t)
		check := request(t, anon, http.MethodGet, hostCardinal,
			"/api/enroll?token="+token, "application/json")
		defer drain(check)
		if check.StatusCode != http.StatusOK {
			t.Errorf("the issued recovery link does not resolve (%d)", check.StatusCode)
		}
	})

	t.Run("the request is spent", func(t *testing.T) {
		resp := postRaw(t, second, secondCSRF,
			"/api/recoveries/e2e-locked-out/approve", "")
		defer drain(resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("a completed request accepted another approval (%d)", resp.StatusCode)
		}
	})
}

// TestNobodyCanRequestTheirOwnRecovery.
//
// Someone who can authenticate does not need recovering, so a self-request is a
// live session being used to mint a second credential without a second person.
func TestNobodyCanRequestTheirOwnRecovery(t *testing.T) {
	c, csrf := adminClient(t)

	resp := postRaw(t, c, csrf, "/api/recoveries", `{"login":"e2e-admin"}`)
	defer drain(resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an administrator opened a recovery request for themselves (%d)",
			resp.StatusCode)
	}
}

// TestUserAdminCannotApproveRecovery.
//
// Recovery can mint a credential on an administrator's account, so it takes the
// broad tier. A narrow one able to approve would reopen the escalation through
// the door built to close it.
func TestUserAdminCannotApproveRecovery(t *testing.T) {
	c, csrf := tieredClient(t, "e2e-user-admin", adminGroupUserAdmins)

	for _, path := range []string{
		"/api/recoveries",
		"/api/recoveries/e2e-admin/approve",
	} {
		resp := postRaw(t, c, csrf, path, `{"login":"e2e-admin"}`)
		drain(resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s returned %d for a user-admin, want 403", path, resp.StatusCode)
		}
	}
}

const adminGroupDirectoryAdmins = "00000000-0000-7000-8000-00000000ad11"

// giveCredential makes an account look enrolled, without a ceremony.
func giveCredential(t *testing.T, login string) {
	t.Helper()
	seedSQL(t, `INSERT INTO webauthn_credentials
	              (entity_id, credential_id, public_key, name)
	            SELECT e.id, decode(md5(random()::text), 'hex'), '\x00'::bytea, 'seeded'
	              FROM entities e WHERE e.name = '`+login+`'
	            ON CONFLICT DO NOTHING`)
}

func postRaw(t *testing.T, c *http.Client, csrf, path, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, //nolint:noctx // bounded by client timeout
		origin(hostCardinal)+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cardinal-CSRF", csrf)

	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
