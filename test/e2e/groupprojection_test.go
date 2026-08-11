package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// What an application is told, against what Cardinal decides.
//
// Against the running stack because the two halves live in different places: a
// Cedar evaluation over the full closure, and a header written afterwards from
// a filtered set. A unit test can hold either and not the seam.

// TestNarrowingWhatAnApplicationSeesDoesNotChangeWhoMayReachIt.
//
// The invariant the whole feature rests on (ADR 0032). forwardauth.go resolves
// one subject and uses it three times — policy input, decision log, headers —
// so narrowing that variable is the obvious way to implement filtering and
// would silently change what Cardinal decides.
//
// Both directions are real. A permit keyed on group membership would start
// refusing people who are members; a forbid keyed on one would stop matching
// and admit somebody it exists to refuse. This asserts the request is admitted
// identically while the disclosure changes underneath it.
func TestNarrowingWhatAnApplicationSeesDoesNotChangeWhoMayReachIt(t *testing.T) {
	t.Cleanup(restoreProjection)

	cardinalCLI(t, "app", "groups", "mode", "protected-app", "all")
	wide := tokenIdentityAtProtectedApp(t)
	if len(wide.Groups) == 0 {
		t.Fatal("the fixture is not telling the application about any groups, so " +
			"this test cannot tell filtering from an empty directory")
	}

	// protected-app owns no groups, so owned mode is the sharpest version of
	// the question: everything the application was told, withdrawn at once.
	cardinalCLI(t, "app", "groups", "mode", "protected-app", "owned")
	narrow := tokenIdentityAtProtectedApp(t)

	// Admitted either way. tokenIdentityAtProtectedApp fails the test on any
	// status but 200, so reaching here twice is the assertion — the person was
	// permitted before and after, by the same policy, on the same membership.
	if len(narrow.Groups) != 0 {
		t.Errorf("the application was still told about %d group(s) after being "+
			"narrowed to the ones it owns, and it owns none", len(narrow.Groups))
	}
	if len(narrow.GroupIDs) != 0 {
		t.Errorf("group identifiers survived the narrowing: %v", narrow.GroupIDs)
	}
}

// TestAnAllowedGroupReachesTheApplicationAgain is the escape hatch, end to end.
//
// Without it the only way to tell an application about a group is to give it
// one, which is not always somebody's to do — the group may predate the
// application by years.
func TestAnAllowedGroupReachesTheApplicationAgain(t *testing.T) {
	t.Cleanup(func() {
		cliBackground("app", "groups", "disallow", "protected-app", "engineers")
		restoreProjection()
	})

	// The group the seeded user is actually in, so the claim has something to
	// carry. Granted here rather than assumed: the suite reseeds.
	tryCardinalCLI(t, "grant", "engineers", tokenOwnerLogin, "-reason", "projection e2e")
	cardinalCLI(t, "app", "groups", "mode", "protected-app", "owned")

	before := tokenIdentityAtProtectedApp(t)
	for _, g := range before.Groups {
		if g == "engineers" {
			t.Fatal("engineers reached the application before it was allowed, so " +
				"this proves nothing about allowing it")
		}
	}

	cardinalCLI(t, "app", "groups", "allow", "protected-app", "engineers")
	after := tokenIdentityAtProtectedApp(t)

	found := false
	for _, g := range after.Groups {
		if g == "engineers" {
			found = true
		}
	}
	if !found {
		t.Errorf("engineers was allowed and still did not reach the application; "+
			"it was told about %v", after.Groups)
	}
}

// TestASystemGroupIsNeverTold.
//
// directory-admins is authority inside Cardinal. An application branching on it
// would be treating a Cardinal internal as one of its own roles, and an
// application that could be granted sight of it would make that a supported
// integration rather than a mistake.
func TestASystemGroupIsNeverTold(t *testing.T) {
	t.Cleanup(restoreProjection)

	cardinalCLI(t, "app", "groups", "mode", "protected-app", "owned")

	// Run directly rather than through cardinalCLI, which fails the test on a
	// non-zero exit — and a refusal is the result being asserted.
	full := append([]string{
		"compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "cardinal", "cardinal",
	}, "app", "groups", "allow", "protected-app", "directory-admins")
	out, err := exec.CommandContext(t.Context(), "docker", full...).CombinedOutput()
	if err == nil {
		t.Fatal("allowing a system group succeeded")
	}
	if !strings.Contains(string(out), "authority inside Cardinal") {
		t.Errorf("refused without saying why: %s", out)
	}
}

// restoreProjection puts the fixture back for whatever runs next.
//
// Not through cardinalCLI: a t.Cleanup runs after t.Context() is cancelled, so
// every command issued from one dies with "context canceled". The tests do not
// depend on this — each sets the mode it needs — but leaving the stack narrowed
// would make the next run of an unrelated header test fail confusingly.
func restoreProjection() {
	cliBackground("app", "groups", "mode", "protected-app", "all")
}

func cliBackground(args ...string) {
	full := append([]string{
		"compose", "-f", "../../examples/compose.yml",
		"exec", "-T", "cardinal", "cardinal",
	}, args...)
	_ = exec.Command("docker", full...).Run() //nolint:errcheck,noctx // best effort cleanup
}
