package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The CLI as an API client.
//
// `cardinal members` no longer opens the database: it presents a session and
// asks the API, so what it may see is decided by policy rather than by holding
// a connection string (ADR 0033).
//
// The browser half of signing in is covered by cliauth_test.go. What is proven
// here is everything after it — the cached session, the client, the request and
// what comes back — by seeding the cache the way a completed sign-in would.

// cliConfigDir is XDG_CONFIG_HOME inside the container. /tmp because it is the
// one directory a distroless image reliably has and the one this user can write
// to; the CLI looks for cardinal/sessions.json beneath it.
const cliConfigDir = "/tmp"

// TestTheCLIReadsMembershipThroughTheAPI.
//
// The assertion that matters is not the output format, it is that the command
// worked at all with no database credential anywhere near it: the container
// runs it with a session and a server URL and nothing else.
func TestTheCLIReadsMembershipThroughTheAPI(t *testing.T) {
	const group = "e2e-client-cli"

	tryCardinalCLI(t, "group", "create", group)
	t.Cleanup(func() { revokeAfterwards(group, "e2e-user") })
	grantFixture(t, group, "e2e-user", "client cli e2e")

	// adminClient seeds the account and its membership of directory-admins.
	// Called for that rather than for the client it returns: signInAs mints a
	// session for an entity, and an entity nothing created has none.
	adminClient(t)
	signInAs(t, "e2e-admin")

	out := clientCLI(t, "members", group)
	if !strings.Contains(out, "e2e-user") {
		t.Errorf("the member is missing from what the command printed:\n%s", out)
	}
	if !strings.Contains(out, "client cli e2e") {
		t.Errorf("the reason is missing, so the command is not showing what the "+
			"API returns:\n%s", out)
	}
}

// TestTheCLIAnswersForAnInstantThatIsNotNow.
//
// The point-in-time endpoints exist so this question does not need the database,
// and this is the command that asks it.
func TestTheCLIAnswersForAnInstantThatIsNotNow(t *testing.T) {
	const group = "e2e-client-cli-at"

	tryCardinalCLI(t, "group", "create", group)
	t.Cleanup(func() { revokeAfterwards(group, "e2e-user") })
	grantFixture(t, group, "e2e-user", "before the revocation")

	time.Sleep(time.Second)
	during := time.Now().UTC().Format(time.RFC3339)
	revokeFixture(t, group, "e2e-user")

	// adminClient seeds the account and its membership of directory-admins.
	// Called for that rather than for the client it returns: signInAs mints a
	// session for an entity, and an entity nothing created has none.
	adminClient(t)
	signInAs(t, "e2e-admin")

	now := clientCLI(t, "members", group)
	if strings.Contains(now, "e2e-user") {
		t.Errorf("the group still lists the member after revoking:\n%s", now)
	}

	then := clientCLI(t, "members", group, "-at", during)
	if !strings.Contains(then, "e2e-user") {
		t.Errorf("asked about %s, the command does not show the member the group "+
			"had then:\n%s", during, then)
	}

	history := clientCLI(t, "history", group, "e2e-user", "-at", during)
	if !strings.Contains(history, "yes") {
		t.Errorf("history was asked whether they were a member then and did not "+
			"say yes:\n%s", history)
	}
	if !strings.Contains(history, "before the revocation") {
		t.Errorf("the reason did not survive the revocation:\n%s", history)
	}
}

// TestTheCLIIsRefusedWhatItsSessionMayNotSee.
//
// The whole point of the move. An ordinary account holds a session, so the
// command runs — and policy decides what it returns, which is what a database
// connection never did.
func TestTheCLIIsRefusedWhatItsSessionMayNotSee(t *testing.T) {
	signInAs(t, "e2e-user")

	out, err := clientCLIRaw(t, "members", "engineers")
	if err == nil {
		t.Fatalf("an ordinary account listed the members of a group:\n%s", out)
	}
	if !strings.Contains(out, "directory-admins") && !strings.Contains(out, "not a member") {
		t.Errorf("the refusal does not say why:\n%s", out)
	}
}

// signInAs seeds the CLI's session cache the way a completed browser sign-in
// would, using a session minted in SQL — the same shape the console tests use.
func signInAs(t *testing.T, login string) {
	t.Helper()

	token := "e2e-cli-" + login + "-token-with-plenty-of-entropy-0123456789"

	seedSQL(t, `DELETE FROM sessions WHERE token_hash = sha256('`+token+`'::bytea)`)
	seedSQL(t, `INSERT INTO sessions
	              (subject_id, token_hash, valid_period, auth_method, auth_at,
	               device_bound, absolute_expiry)
	            SELECT e.id, sha256('`+token+`'::bytea),
	                   tstzrange(now(), now() + interval '1 hour'), 'passkey', now(),
	                   true, now() + interval '7 days'
	              FROM entities e WHERE e.name = '`+login+`'`)

	cache, err := json.Marshal(map[string]any{
		"sessions": map[string]any{
			cliServer: map[string]any{
				"token":       token,
				"login":       login,
				"deviceBound": true,
				// Far enough ahead that the cache offers it; the server decides
				// the real lifetime.
				"expiresAt": time.Now().Add(30 * time.Minute).Format(time.RFC3339Nano),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Copied in as a directory rather than written with a shell: the image is
	// distroless, so there is no /bin/sh, no mkdir and no cat in it — and
	// `docker cp` of a directory creates the directory, which `docker cp` of a
	// file into a missing one does not.
	local := filepath.Join(t.TempDir(), "cardinal")
	if err := os.MkdirAll(local, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "sessions.json"), cache, 0o600); err != nil {
		t.Fatal(err)
	}
	// The container runs as nonroot and `docker cp` preserves both the mode and
	// the owner, so a 0700 directory owned by this user is one the container's
	// user cannot enter — which looks exactly like no cache at all, because the
	// CLI treats an unreadable cache as "not signed in".
	if err := os.Chmod(local, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(local, "sessions.json"), 0o644); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.CommandContext(t.Context(), "docker", "cp",
		local, containerID(t)+":"+cliConfigDir+"/").CombinedOutput(); err != nil {
		t.Fatalf("copying the CLI session cache in: %v\n%s", err, out)
	}
}

// cliServer is the address the CLI is pointed at from inside the container.
const cliServer = "http://localhost:8080"

func clientCLI(t *testing.T, args ...string) string {
	t.Helper()

	out, err := clientCLIRaw(t, args...)
	if err != nil {
		t.Fatalf("cardinal %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func clientCLIRaw(t *testing.T, args ...string) (string, error) {
	t.Helper()

	full := append([]string{
		"compose", "-f", "../../examples/compose.yml", "exec",
		"-e", "XDG_CONFIG_HOME=" + cliConfigDir,
		"-e", "CARDINAL_SERVER=" + cliServer,
		"-T", "cardinal", "cardinal",
	}, args...)
	out, err := exec.CommandContext(t.Context(), "docker", full...).CombinedOutput()
	return string(out), err
}

// TestPassingADSNToAClientCommandExplainsTheRule.
//
// Not a barrier — nothing downstream declares the flag, so the command's own
// parser refuses it regardless. What is asserted is the sentence: somebody who
// types the habit of the last twenty commands should learn the rule rather than
// read the word "usage".
func TestPassingADSNToAClientCommandExplainsTheRule(t *testing.T) {
	out, err := clientCLIRaw(t, "members", "engineers", "-dsn", "postgres://nowhere")
	if err == nil {
		t.Fatalf("a client command accepted -dsn:\n%s", out)
	}
	for _, want := range []string{"signs in rather than opening the database", "-server", "migrate"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, out)
		}
	}
}
