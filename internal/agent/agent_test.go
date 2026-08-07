package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/agent"
	"github.com/arthur-lonfils/cardinal/internal/hostclient"
	"golang.org/x/crypto/ssh"
)

func sample() *agent.Assignment {
	return &agent.Assignment{
		Host: "web-01.prod",
		Users: []agent.AssignedUser{{
			Name: "alice", UID: 100000, GID: 100000,
			Home: "/home/alice", Shell: "/bin/bash", Groups: []int{100002},
		}},
		Groups: []agent.AssignedGroup{{
			Name: "sre", GID: 100002, Members: []string{"alice"},
		}},
	}
}

func testIdentity(t *testing.T, server string) *hostclient.Identity {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return &hostclient.Identity{Server: server, Signer: signer}
}

// TestSnapshotSynthesisesTheUserPrivateGroup.
//
// Cardinal does not send it, because there is nothing to send: the convention
// *is* the record — same name, same number as the user. Without it `ls -l`
// shows a bare number in the group column and `getent group alice` finds
// nothing, which looks like a directory problem rather than a missing
// convention.
func TestSnapshotSynthesisesTheUserPrivateGroup(t *testing.T) {
	s := agent.NewSnapshot(sample())

	group, ok := s.GroupByName("alice")
	if !ok {
		t.Fatal("the user-private group was not synthesised")
	}
	if group.GID != 100000 {
		t.Fatalf("gid %d, want the user's own uid", group.GID)
	}

	byGID, ok := s.GroupByGID(100000)
	if !ok || byGID.GroupName != "alice" {
		t.Fatalf("gid 100000 resolves to %+v", byGID)
	}
}

// TestASentGroupIsNotOverwrittenByASynthesisedOne.
//
// If a directory group happened to hold a gid equal to somebody's uid, the real
// one wins. It should not be possible — one allocator hands out both, so they
// cannot collide — but "should not be possible" is a claim about a different
// package, and the consequence here is a group silently renamed.
func TestASentGroupIsNotOverwrittenByASynthesisedOne(t *testing.T) {
	a := sample()
	a.Groups = append(a.Groups, agent.AssignedGroup{
		Name: "collision", GID: 100000, Members: []string{"bob"},
	})

	s := agent.NewSnapshot(a)

	group, ok := s.GroupByGID(100000)
	if !ok {
		t.Fatal("gid 100000 does not resolve")
	}
	if group.GroupName != "collision" {
		t.Fatalf("the synthesised group displaced the real one: %+v", group)
	}
}

// TestMembershipsComeFromSentGroupsOnly.
//
// `id alice` must show sre. The user-private group is not a membership — glibc
// gets it from the passwd record's gid — and emitting it as one would list
// alice twice.
func TestMembershipsComeFromSentGroupsOnly(t *testing.T) {
	s := agent.NewSnapshot(sample())

	found := s.MembershipsOf("alice", "")
	if len(found) != 1 {
		t.Fatalf("got %d memberships, want 1: %+v", len(found), found)
	}
	if found[0].GroupName != "sre" {
		t.Fatalf("wrong group: %+v", found[0])
	}
}

// TestCacheRoundTrips.
func TestCacheRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assignment.json")

	original := sample()
	original.FetchedAt = time.Now().Truncate(time.Second)
	if err := agent.Save(path, original); err != nil {
		t.Fatal(err)
	}

	loaded, err := agent.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Host != "web-01.prod" || len(loaded.Users) != 1 {
		t.Fatalf("wrong assignment: %+v", loaded)
	}
	if !loaded.FetchedAt.Equal(original.FetchedAt) {
		t.Fatalf("fetched-at did not survive: %s vs %s",
			loaded.FetchedAt, original.FetchedAt)
	}
}

// TestSaveReplacesAtomically.
//
// A truncated cache left by a power cut would start the agent with no
// identities while the file sat there looking fine. Checked by proving the
// previous contents are intact until the moment they are replaced — the write
// goes to a temp file in the same directory, which is also what makes the
// rename atomic rather than a copy across filesystems.
func TestSaveReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "assignment.json")

	if err := agent.Save(path, sample()); err != nil {
		t.Fatal(err)
	}

	second := sample()
	second.Host = "web-02.prod"
	if err := agent.Save(path, second); err != nil {
		t.Fatal(err)
	}

	loaded, err := agent.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Host != "web-02.prod" {
		t.Fatalf("the replacement did not take: %s", loaded.Host)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "assignment.json" {
			t.Fatalf("a temporary file was left behind: %s", e.Name())
		}
	}
}

// TestMissingCacheIsDistinguishable.
//
// A host that has never refreshed is a different problem from a cache that is
// there and broken: the first is normal on a new machine, the second means
// somebody should look at the file. Continuing silently past the second would
// leave a machine serving nothing.
func TestMissingCacheIsDistinguishable(t *testing.T) {
	a := &agent.Agent{CachePath: filepath.Join(t.TempDir(), "absent.json")}

	_, err := a.LoadCache()
	if err == nil {
		t.Fatal("loading an absent cache must fail")
	}
	if !agent.CacheMissing(err) {
		t.Fatalf("not recognised as a missing cache: %v", err)
	}

	corrupt := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{\"host\": \"web-01"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := &agent.Agent{CachePath: corrupt}
	_, err = b.LoadCache()
	if err == nil {
		t.Fatal("a truncated cache must fail to load")
	}
	if agent.CacheMissing(err) {
		t.Fatal("a corrupt cache must not be reported as an absent one")
	}
}

// TestRefreshUpdatesCacheAndSnapshot.
func TestRefreshUpdatesCacheAndSnapshot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/hosts/assignment" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			// The signature travels; the test server does not verify it, which
			// is what the end-to-end suite is for. What matters here is that
			// the agent sends one at all.
			if r.Header.Get("Authorization") == "" {
				t.Error("the agent sent an unsigned request")
			}
			_ = json.NewEncoder(w).Encode(sample())
		}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "assignment.json")
	a := &agent.Agent{
		Identity:  testIdentity(t, server.URL),
		CachePath: path,
	}

	if a.Source() != nil {
		t.Fatal("a fresh agent must have no source; ServiceNotAvailable depends on it")
	}

	if _, err := a.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}

	source := a.Source()
	if source == nil {
		t.Fatal("the snapshot was not installed")
	}
	if _, ok := source.UserByName("alice"); !ok {
		t.Fatal("alice does not resolve after a refresh")
	}

	cached, err := agent.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cached.Host != "web-01.prod" {
		t.Fatalf("the cache was not written: %+v", cached)
	}
}

// TestAnOutageDoesNotClearWhatIsServed.
//
// The property the whole agent exists for. An agent that dropped its records
// when Cardinal became unreachable would turn a directory outage into a fleet
// outage — everyone locked out of every machine at once, which is precisely the
// failure that makes people distrust centralised identity.
func TestAnOutageDoesNotClearWhatIsServed(t *testing.T) {
	reachable := true
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			if !reachable {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"authorization unavailable"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(sample())
		}))
	defer server.Close()

	a := &agent.Agent{
		Identity:  testIdentity(t, server.URL),
		CachePath: filepath.Join(t.TempDir(), "assignment.json"),
	}

	if _, err := a.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}

	reachable = false
	if _, err := a.Refresh(t.Context()); err == nil {
		t.Fatal("a 503 must be reported as a failure")
	}

	source := a.Source()
	if source == nil {
		t.Fatal("the outage cleared the snapshot")
	}
	if _, ok := source.UserByName("alice"); !ok {
		t.Fatal("alice stopped resolving because Cardinal was unreachable")
	}
}

// TestARebootDuringAnOutageStillResolves.
//
// The same property across a process restart, which is the case /var/lib
// exists for: a cache in /run would be empty after a reboot, and a machine
// coming up during an outage is exactly when this has to work.
func TestARebootDuringAnOutageStillResolves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assignment.json")

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(sample())
		}))

	before := &agent.Agent{Identity: testIdentity(t, server.URL), CachePath: path}
	if _, err := before.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	server.Close() // Cardinal is now gone, and stays gone.

	// A brand-new Agent, as after a reboot.
	after := &agent.Agent{Identity: testIdentity(t, server.URL), CachePath: path}
	if _, err := after.LoadCache(); err != nil {
		t.Fatal(err)
	}

	source := after.Source()
	if source == nil {
		t.Fatal("a restarted agent has nothing to serve")
	}
	record, ok := source.UserByName("alice")
	if !ok {
		t.Fatal("alice does not resolve from the cache")
	}
	if record.HomeDirectory != "/home/alice" {
		t.Fatalf("the cached record is incomplete: %+v", record)
	}

	if _, err := after.Refresh(t.Context()); err == nil {
		t.Fatal("the refresh should have failed; Cardinal is stopped")
	}
	if after.Source() == nil {
		t.Fatal("the failed refresh cleared the cache-loaded snapshot")
	}
}

// TestRunKeepsGoingAfterAFailure.
//
// A failed refresh must be a log line, not an exit. An agent that stopped on
// the first network blip would need a supervisor to notice and restart it, and
// in the meantime nothing on the machine would resolve.
func TestRunKeepsGoingAfterAFailure(t *testing.T) {
	var attempts int
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			attempts++
			if attempts == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(sample())
		}))
	defer server.Close()

	a := &agent.Agent{
		Identity:  testIdentity(t, server.URL),
		CachePath: filepath.Join(t.TempDir(), "assignment.json"),
		Interval:  10 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for a.Source() == nil {
		select {
		case <-deadline:
			t.Fatal("the agent never recovered from the first failure")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run returned an error: %v", err)
	}
	if attempts < 2 {
		t.Fatalf("only %d attempts — Run stopped at the first failure", attempts)
	}
}

// TestFetchWritesNothing.
//
// Shadow mode's entire claim. An earlier version of it called Refresh, which
// writes the cache to /var/lib, renders sudoers and renews the certificate —
// while the command's own help text said it changes nothing.
func TestFetchWritesNothing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(sample())
		}))
	defer server.Close()

	dir := t.TempDir()
	a := &agent.Agent{
		Identity: testIdentity(t, server.URL),
		// Every path pointed somewhere observable, so anything written shows up.
		CachePath:      filepath.Join(dir, "assignment.json"),
		SudoersPath:    filepath.Join(dir, "50-cardinal"),
		HostKeyPath:    filepath.Join(dir, "ssh_host_ed25519_key.pub"),
		HostCertPath:   filepath.Join(dir, "cert.pub"),
		SSHDDropInPath: filepath.Join(dir, "50-cardinal.conf"),
	}

	fetched, err := a.Fetch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if fetched.Host != "web-01.prod" {
		t.Fatalf("wrong assignment: %+v", fetched)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Fetch wrote %d file(s): %v", len(entries), entries)
	}

	// And nothing was installed in memory either, so a shadow run cannot start
	// answering lookups as a side effect.
	if a.Source() != nil {
		t.Fatal("Fetch installed a snapshot")
	}
}

// TestStatusReportsUnnumberedUsers.
//
// The silent failure: policy allows the login, a certificate is issued, and
// sshd refuses because the host cannot resolve the name. Nothing in that chain
// says why, so it has to survive into the cache to be reportable.
func TestStatusReportsUnnumberedUsers(t *testing.T) {
	a := sample()
	a.Unnumbered = []string{"carol"}

	path := filepath.Join(t.TempDir(), "assignment.json")
	if err := agent.Save(path, a); err != nil {
		t.Fatal(err)
	}

	loaded, err := agent.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(loaded.Unnumbered, "carol") {
		t.Fatalf("the unnumbered list did not survive the cache: %v", loaded.Unnumbered)
	}
}
