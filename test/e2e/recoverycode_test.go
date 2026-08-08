package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// Spending a recovery code.
//
// The path had a beginning and no end: codes could be generated and counted,
// and store.RedeemRecoveryCode was written and tested and called by nothing. So
// the second phase-0 non-negotiable produced something a person could print and
// then had nowhere to type.
//
// A code redeems into an enrollment rather than a session, because credential
// self-service is behind requireDeviceBound and a string on paper is not a
// device-bound credential — a session minted from one could not register the
// passkey the whole exercise exists to register.

// generateCodes gives the seeded account a fresh set and returns them.
func generateCodes(t *testing.T) []string {
	t.Helper()

	c := client(t)
	withSession(t, c)
	freshenSession(t)

	var out struct {
		Codes []string `json:"codes"`
	}
	resp := post(t, c, "/api/recovery/codes", csrfToken(t, c), "", map[string]string{}, &out)
	defer drain(resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("generating recovery codes returned %d", resp.StatusCode)
	}
	if len(out.Codes) == 0 {
		t.Fatal("no codes were issued")
	}
	return out.Codes
}

// freshenSession makes the seeded session count as recently authenticated.
//
// Generating codes is a step-up action: it mints account-recovery authority in
// plain text, so policy asks for a passkey used in the last few minutes. The
// seeded session's timestamp is whenever the suite started.
func freshenSession(t *testing.T) {
	t.Helper()
	seedSQL(t, `UPDATE sessions SET auth_at = now()
	             WHERE token_hash = sha256('e2e-session-token-with-plenty-of-entropy-0123456789abcdef'::bytea)`)
}

// TestARecoveryCodeGetsYouBackIn.
func TestARecoveryCodeGetsYouBackIn(t *testing.T) {
	codes := generateCodes(t)

	var enrollment struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expiresAt"`
	}
	anon := client(t)
	resp := post(t, anon, "/api/recovery/codes/redeem", csrfToken(t, anon), "",
		map[string]string{"login": "e2e-user", "code": codes[0]}, &enrollment)
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redeeming returned %d, want 200", resp.StatusCode)
	}
	if enrollment.Token == "" {
		t.Fatal("no enrollment token — the code was spent for nothing")
	}

	// And the token is one the existing enrollment path accepts, which is the
	// point of returning an enrollment rather than inventing a second way in.
	details := request(t, client(t), http.MethodGet, hostCardinal,
		"/api/enroll?token="+enrollment.Token, "")
	defer drain(details)
	if details.StatusCode != http.StatusOK {
		t.Fatalf("the enrollment path rejected the token recovery issued: %d",
			details.StatusCode)
	}
}

// TestARecoveryCodeWorksOnce.
func TestARecoveryCodeWorksOnce(t *testing.T) {
	codes := generateCodes(t)

	anon := client(t)
	first := post(t, anon, "/api/recovery/codes/redeem", csrfToken(t, anon), "",
		map[string]string{"login": "e2e-user", "code": codes[1]}, nil)
	defer drain(first)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("the first redemption returned %d, want 200", first.StatusCode)
	}

	again := client(t)
	second := post(t, again, "/api/recovery/codes/redeem", csrfToken(t, again), "",
		map[string]string{"login": "e2e-user", "code": codes[1]}, nil)
	defer drain(second)
	if second.StatusCode != http.StatusUnauthorized {
		t.Errorf("the same code was accepted twice (%d) — a sheet of paper somebody "+
			"finds is then a permanent way in", second.StatusCode)
	}
}

// TestRedeemingDoesNotSayWhoExists.
//
// An unauthenticated endpoint that answers differently for a real account and
// an imaginary one is a way to ask whether somebody works here. The rate limit
// bounds how fast, and the answer being identical is what makes the question
// pointless.
func TestRedeemingDoesNotSayWhoExists(t *testing.T) {
	cases := []struct{ name, login, code string }{
		{"real account, wrong code", "e2e-user", "AAAAA-BBBBB-CCCCC"},
		{"no such account", "nobody-by-that-name", "AAAAA-BBBBB-CCCCC"},
	}

	var answers []string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			anon := client(t)
			resp := post(t, anon, "/api/recovery/codes/redeem", csrfToken(t, anon), "",
				map[string]string{"login": tc.login, "code": tc.code}, nil)
			defer drain(resp)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("returned %d, want 401", resp.StatusCode)
			}
			body := make([]byte, 512)
			n, _ := resp.Body.Read(body) //nolint:errcheck // the comparison below is the assertion
			answers = append(answers, strings.TrimSpace(string(body[:n])))
		})
	}

	if len(answers) == 2 && answers[0] != answers[1] {
		t.Errorf("the two answers differ, which tells a stranger which logins exist:\n"+
			"  real:      %s\n  imaginary: %s", answers[0], answers[1])
	}
}
