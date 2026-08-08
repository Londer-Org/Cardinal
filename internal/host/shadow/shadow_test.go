package shadow_test

import (
	"context"
	"testing"

	"go.londer.be/cardinal/internal/host/shadow"
)

// fakeSystem is a machine with whatever NSS is currently telling it.
type fakeSystem struct {
	users map[string]shadow.PosixRecord
	sudo  map[string]bool
}

func (f fakeSystem) LookupUser(_ context.Context, name string) (shadow.PosixRecord, bool, error) {
	record, ok := f.users[name]
	return record, ok, nil
}

func (f fakeSystem) SudoAllowed(_ context.Context, name string) (bool, error) {
	return f.sudo[name], nil
}

func findingFor(t *testing.T, report *shadow.Report, user, what string) shadow.Finding {
	t.Helper()
	for _, f := range report.Findings {
		if f.User == user && f.What == what {
			return f
		}
	}
	t.Fatalf("no %q finding for %s in %+v", what, user, report.Findings)
	return shadow.Finding{}
}

// TestAUIDMismatchIsBlocking.
//
// The one finding the whole package exists for. If the machine says alice is
// 1234 and Cardinal says 100003, cutting over hands every file she owns to a
// stranger — the filesystem recorded a number, and nothing afterwards undoes it.
func TestAUIDMismatchIsBlocking(t *testing.T) {
	system := fakeSystem{
		users: map[string]shadow.PosixRecord{
			"alice": {UID: 1234, GID: 1234, Home: "/home/alice", Shell: "/bin/bash"},
		},
	}

	report, err := shadow.Compare(t.Context(), "web-01.prod", []shadow.Expected{{
		Name: "alice", UID: 100003, GID: 100003,
		Home: "/home/alice", Shell: "/bin/bash",
	}}, nil, system)
	if err != nil {
		t.Fatal(err)
	}

	uid := findingFor(t, report, "alice", "uid")
	if uid.Severity != shadow.Blocking {
		t.Fatalf("a uid mismatch is %q, want blocking", uid.Severity)
	}
	if uid.Why == "" {
		t.Fatal("a blocking finding must say what happens")
	}
	if len(report.Blocking()) == 0 {
		t.Fatal("the report does not report itself as blocking")
	}
}

// TestMatchingIdentityIsNotBlocking.
//
// The case a migration is aiming for, and the one that makes the test above
// mean something: a report that called everything blocking would pass it too.
func TestMatchingIdentityIsNotBlocking(t *testing.T) {
	system := fakeSystem{
		users: map[string]shadow.PosixRecord{
			"alice": {UID: 100003, GID: 100003, Home: "/home/alice", Shell: "/bin/bash"},
		},
	}

	report, err := shadow.Compare(t.Context(), "web-01.prod", []shadow.Expected{{
		Name: "alice", UID: 100003, GID: 100003,
		Home: "/home/alice", Shell: "/bin/bash",
	}}, nil, system)
	if err != nil {
		t.Fatal(err)
	}

	if blocking := report.Blocking(); len(blocking) != 0 {
		t.Fatalf("an identical account was reported as blocking: %+v", blocking)
	}
	if findingFor(t, report, "alice", "uid").Severity != shadow.Match {
		t.Fatal("an identical uid was not reported as matching")
	}
}

// TestANewAccountIsAdditive.
//
// Somebody Cardinal knows and the machine does not. Nothing existing is
// disturbed, so this must not stop a cutover — a report that blocked on every
// new person would block on every migration.
func TestANewAccountIsAdditive(t *testing.T) {
	report, err := shadow.Compare(t.Context(), "web-01.prod", []shadow.Expected{{
		Name: "newcomer", UID: 100009, GID: 100009,
		Home: "/home/newcomer", Shell: "/bin/bash",
	}}, nil, fakeSystem{})
	if err != nil {
		t.Fatal(err)
	}

	account := findingFor(t, report, "newcomer", "account")
	if account.Severity != shadow.Additive {
		t.Fatalf("a new account is %q, want additive", account.Severity)
	}
	if len(report.Blocking()) != 0 {
		t.Fatal("a new account blocked the cutover")
	}
}

// TestSudoChangesAreReviewable.
//
// Both directions, and neither is blocking: gaining root is a decision somebody
// makes, losing it is an inconvenience, and neither destroys anything.
func TestSudoChangesAreReviewable(t *testing.T) {
	system := fakeSystem{
		users: map[string]shadow.PosixRecord{
			"gaining": {UID: 1, GID: 1},
			"losing":  {UID: 2, GID: 2},
			"keeping": {UID: 3, GID: 3},
		},
		sudo: map[string]bool{"losing": true, "keeping": true},
	}

	report, err := shadow.Compare(t.Context(), "web-01.prod", []shadow.Expected{
		{Name: "gaining", UID: 1, GID: 1, Sudo: true},
		{Name: "losing", UID: 2, GID: 2, Sudo: false},
		{Name: "keeping", UID: 3, GID: 3, Sudo: true},
	}, nil, system)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		user string
		want shadow.Severity
		why  string
	}{
		{"gaining", shadow.Review, "gains root"},
		{"losing", shadow.Review, "loses root"},
		{"keeping", shadow.Match, ""},
	} {
		got := findingFor(t, report, tc.user, "sudo")
		if got.Severity != tc.want {
			t.Fatalf("%s: sudo is %q, want %q", tc.user, got.Severity, tc.want)
		}
	}

	if len(report.Blocking()) != 0 {
		t.Fatal("a sudo change blocked the cutover; only uid and gid should")
	}
}

// TestGroupsGainedAndLost.
func TestGroupsGainedAndLost(t *testing.T) {
	system := fakeSystem{
		users: map[string]shadow.PosixRecord{
			"alice": {UID: 1, GID: 1, Groups: []string{"ipausers", "sre"}},
		},
	}

	report, err := shadow.Compare(t.Context(), "web-01.prod", []shadow.Expected{{
		Name: "alice", UID: 1, GID: 1, Groups: []string{"sre", "platform"},
	}}, nil, system)
	if err != nil {
		t.Fatal(err)
	}

	lost := findingFor(t, report, "alice", "groups lost")
	if lost.Local != "ipausers" {
		t.Fatalf("wrong lost groups: %q", lost.Local)
	}
	if lost.Severity != shadow.Review {
		t.Fatalf("losing a group is %q, want review", lost.Severity)
	}

	gained := findingFor(t, report, "alice", "groups gained")
	if gained.Cardinal != "platform" {
		t.Fatalf("wrong gained groups: %q", gained.Cardinal)
	}
}

// TestHomeAndShellAreReviewNotBlocking.
//
// A home directory change is a rename at worst — the files are still there and
// still owned by the same uid. Treating it as blocking would put a stop sign in
// front of every migration that tidies up paths, which is most of them.
func TestHomeAndShellAreReviewNotBlocking(t *testing.T) {
	system := fakeSystem{
		users: map[string]shadow.PosixRecord{
			"alice": {UID: 1, GID: 1, Home: "/export/home/alice", Shell: "/bin/ksh"},
		},
	}

	report, err := shadow.Compare(t.Context(), "web-01.prod", []shadow.Expected{{
		Name: "alice", UID: 1, GID: 1, Home: "/home/alice", Shell: "/bin/bash",
	}}, nil, system)
	if err != nil {
		t.Fatal(err)
	}

	if findingFor(t, report, "alice", "home").Severity != shadow.Review {
		t.Fatal("a home directory change should be reviewable, not blocking")
	}
	if findingFor(t, report, "alice", "shell").Severity != shadow.Review {
		t.Fatal("a shell change should be reviewable, not blocking")
	}
	if len(report.Blocking()) != 0 {
		t.Fatal("a path change blocked the cutover")
	}
}

// TestAGIDMismatchIsAlsoBlocking.
//
// Same reason as the uid: group ownership of every file the account created
// changes, and the filesystem recorded the number.
func TestAGIDMismatchIsAlsoBlocking(t *testing.T) {
	system := fakeSystem{
		users: map[string]shadow.PosixRecord{"alice": {UID: 100003, GID: 500}},
	}

	report, err := shadow.Compare(t.Context(), "web-01.prod", []shadow.Expected{{
		Name: "alice", UID: 100003, GID: 100003,
	}}, nil, system)
	if err != nil {
		t.Fatal(err)
	}

	if findingFor(t, report, "alice", "gid").Severity != shadow.Blocking {
		t.Fatal("a gid mismatch must block")
	}
}

// TestSomebodyCardinalHasNeverHeardOf.
//
// Named with -users, because enumeration is usually off on both sides. The question is
// "does Cardinal know them at all", and answering it by comparing against an
// empty record would say Cardinal wants uid 0 — which is what a live run
// actually produced for root before this existed.
func TestSomebodyCardinalHasNeverHeardOf(t *testing.T) {
	system := fakeSystem{
		users: map[string]shadow.PosixRecord{
			"root": {UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"},
		},
	}

	report, err := shadow.Compare(t.Context(), "web-01.prod", nil,
		[]string{"root", "nobody-at-all"}, system)
	if err != nil {
		t.Fatal(err)
	}

	if blocking := report.Blocking(); len(blocking) != 0 {
		t.Fatalf("root was reported as about to be renumbered: %+v", blocking)
	}

	found := findingFor(t, report, "root", "unknown to Cardinal")
	if found.Severity != shadow.Review {
		t.Fatalf("got %q, want review", found.Severity)
	}
	if found.Local != "0" {
		t.Fatalf("the local uid is %q, want 0", found.Local)
	}

	if len(report.Unchecked) != 1 || report.Unchecked[0] != "nobody-at-all" {
		t.Fatalf("a name neither system knows was not recorded: %v", report.Unchecked)
	}
}

// TestNamingSomebodyTwiceDoesNotDoubleReport.
func TestNamingSomebodyTwiceDoesNotDoubleReport(t *testing.T) {
	system := fakeSystem{
		users: map[string]shadow.PosixRecord{"alice": {UID: 100003, GID: 100003}},
	}

	report, err := shadow.Compare(t.Context(), "web-01.prod",
		[]shadow.Expected{{Name: "alice", UID: 100003, GID: 100003}},
		[]string{"alice"}, system)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range report.Findings {
		if f.What == "unknown to Cardinal" {
			t.Fatalf("alice is in the assignment and was also reported as unknown: %+v", f)
		}
	}
}
