package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/server/policy"
)

func shipped(t *testing.T) string {
	t.Helper()
	document, err := os.ReadFile(filepath.Join(repoRoot(t), "policies", "cardinal.cedar"))
	require.NoError(t, err)
	return string(document)
}

// TestRoundTripPreservesEverythingItDidNotTouch.
//
// The property the whole design rests on. A deployment's policy set carries the
// reasoning for each rule in comments above it, and a structured editor that
// reformatted the file on save would discard all of it — turning a convenience
// into a way to lose why somebody has access.
//
// Adding a rule to Cardinal's own shipped set, which is mostly comment, and
// asserting the original survives byte for byte.
func TestRoundTripPreservesEverythingItDidNotTouch(t *testing.T) {
	original := shipped(t)

	after, err := policy.Add(original, policy.Rule{
		ID:                  "contractors-may-reach-the-wiki",
		Kind:                policy.KindWebAccess,
		PrincipalGroup:      "00000000-0000-7000-8000-00000000c0f1",
		ResourceApplication: "wiki",
	})
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(after, strings.TrimRight(original, " \t\n")),
		"adding a rule rewrote something above it")
	assert.Contains(t, after, "// Cardinal's default policy set.",
		"the file's own header comment did not survive")
	assert.Contains(t, after, "looks like a working deny",
		"a comment in the middle of the file did not survive")
}

// TestRemovingTakesTheCommentWithIt.
//
// The other half, and the one that is a judgement rather than a mechanism: a
// paragraph explaining why the SRE team may reach production, left behind after
// the rule granting it is gone, is worse than no comment at all.
func TestRemovingTakesTheCommentWithIt(t *testing.T) {
	const document = `
// Why the SRE team may reach production. A paragraph of reasoning that
// belongs to exactly one rule.
@id("sre-web")
permit (
    principal in Cardinal::Group::"00000000-0000-7000-8000-0000000e5be1",
    action == Cardinal::Action::"AccessURL",
    resource in Cardinal::Group::"00000000-0000-7000-8000-0000000e5be0"
);

// A different rule, with a comment of its own.
@id("everyone-web")
permit (
    principal,
    action == Cardinal::Action::"AccessURL",
    resource in Cardinal::Group::"00000000-0000-7000-8000-0000000e5be0"
);`

	after, err := policy.Remove(document, "sre-web")
	require.NoError(t, err)

	assert.NotContains(t, after, "Why the SRE team may reach production",
		"the comment describing the removed rule stayed behind")
	assert.Contains(t, after, "A different rule, with a comment of its own.",
		"the surviving rule lost its comment")
	assert.Contains(t, after, `@id("everyone-web")`)
}

// TestSemicolonInsideAStringDoesNotSplitARule.
//
// Splitting on ";" would cut this rule in half and produce two fragments,
// neither of which parses, from a document that was fine. A path or a URL in a
// condition is an entirely ordinary thing to write.
func TestSemicolonInsideAStringDoesNotSplitARule(t *testing.T) {
	const document = `@id("odd-but-legal")
permit (
    principal,
    action == Cardinal::Action::"AccessURL",
    resource
)
when { context has path && context.path == "/a;b" };`

	rules, err := policy.Parse(document)
	require.NoError(t, err)
	require.Len(t, rules, 1, "the rule was split at the semicolon inside the string")
	assert.Equal(t, "odd-but-legal", rules[0].ID)
}

// TestACommentInsideAStringIsNotAComment: "https://example.com" contains what
// looks exactly like the start of a comment, and stripping it would corrupt
// every redirect URI anybody ever writes into a condition.
func TestACommentInsideAStringIsNotAComment(t *testing.T) {
	const document = `@id("has-a-url")
permit (
    principal,
    action == Cardinal::Action::"AccessURL",
    resource
)
when { context has host && context.host == "https://example.com" };`

	rules, err := policy.Parse(document)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Contains(t, rules[0].Source, "https://example.com")
}

// TestComposedRulesSurviveAParse is the round trip that matters: everything
// this renders, it must recognise. Otherwise a rule added from the console
// appears as hand-written the moment the page reloads, and cannot be removed
// the way it was added.
func TestComposedRulesSurviveAParse(t *testing.T) {
	cases := []policy.Rule{
		{
			ID: "staff-may-reach-staff-apps", Kind: policy.KindWebAccess,
			PrincipalGroup: policy.Everyone,
			ResourceGroup:  "00000000-0000-7000-8000-0000000e5be0",
		},
		{
			ID: "engineering-may-sign-in-to-grafana", Kind: policy.KindAppAccess,
			PrincipalGroup:      "00000000-0000-7000-8000-00000000e001",
			ResourceApplication: "grafana",
		},
		{
			ID: "sre-may-log-into-production", Kind: policy.KindSSHLogin,
			PrincipalGroup: "00000000-0000-7000-8000-0000000e5be1",
			ResourceGroup:  "00000000-0000-7000-8000-0000000e5be2",
			LocalAccounts:  []string{"deploy", "www-data"},
		},
		{
			ID: "engineers-may-log-in-as-themselves", Kind: policy.KindSSHLogin,
			PrincipalGroup: "00000000-0000-7000-8000-0000000e5be3",
			ResourceGroup:  "00000000-0000-7000-8000-0000000e5be4",
			LocalAccounts:  []string{policy.AccountOwnLogin},
		},
		{
			ID: "platform-admins-may-run-as-root", Kind: policy.KindRunAsRoot,
			PrincipalGroup: "00000000-0000-7000-8000-0000000e5be5",
			ResourceGroup:  "00000000-0000-7000-8000-0000000e5be4",
		},
		{
			ID: "anyone-may-sign-in-anywhere", Kind: policy.KindAppAccess,
			PrincipalGroup: policy.Everyone,
			ResourceGroup:  policy.Anything,
		},
	}

	for _, want := range cases {
		t.Run(want.ID, func(t *testing.T) {
			rendered, err := policy.Render(want)
			require.NoError(t, err)

			// It compiles, which is the first thing that must be true of
			// anything this writes into a policy set.
			_, err = policy.NewEngine([]byte(rendered), 0)
			require.NoError(t, err, "composed a rule Cedar will not accept:\n%s", rendered)

			parsed, err := policy.Parse(rendered)
			require.NoError(t, err)
			require.Len(t, parsed, 1)

			got := parsed[0]
			got.Source = ""
			assert.Equal(t, want, got,
				"a rule this composed came back as something else:\n%s", rendered)
		})
	}
}

// TestTheShippedSetIsMostlyManageable.
//
// Not every rule, and the ones left out are the point: the forbids and the
// administration tiers are the guardrails the composable rules sit inside.
// If this number drifts upward, something that should have stayed hand-written
// became editable with a click.
func TestTheShippedSetIsMostlyManageable(t *testing.T) {
	rules, err := policy.Parse(shipped(t))
	require.NoError(t, err)

	byKind := map[policy.RuleKind][]string{}
	for _, r := range rules {
		byKind[r.Kind] = append(byKind[r.Kind], r.ID)
	}

	assert.ElementsMatch(t, []string{
		"directory-admins-may-administer",
		"user-admins-may-manage-people",
		"security-admins-may-manage-applications",
		"admin-requires-fresh-device-bound-auth",
		"ssh-requires-device-bound",
		"root-requires-recent-auth",
		// Provisioning. Hand-written on purpose: it is read together with the
		// step-up forbid it deliberately escapes, and a rule whose whole point
		// is an exception to a guardrail should not be one a form produces.
		"provisioners-may-provision",
	}, byKind[policy.KindOther],
		"the set of hand-written rules changed — check that a guardrail did not "+
			"become removable with a click, or a manageable rule stop being one")
}

// TestAGuardrailCannotBeRemovedFromHere.
//
// The step-up forbid is what makes membership of directory-admins insufficient
// on its own. Removing it is a legitimate thing to want and not a legitimate
// thing to do with one click, so it goes through the policy file, where the
// change is reviewed as text.
func TestAGuardrailCannotBeRemovedFromHere(t *testing.T) {
	_, err := policy.Remove(shipped(t), "admin-requires-fresh-device-bound-auth")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "written by hand")
	assert.Contains(t, err.Error(), "publishing an edited policy set",
		"the refusal has to say what to do instead, or it is just an obstacle")
}

// TestRootIsNotAnSSHPrincipal.
//
// Becoming root is a separate action with a stricter rule — fifteen minutes of
// freshness. A certificate whose principals included root would have granted it
// without that rule ever being consulted, so the builder must not be able to
// write one.
func TestRootIsNotAnSSHPrincipal(t *testing.T) {
	_, err := policy.Render(policy.Rule{
		ID: "sneaky", Kind: policy.KindSSHLogin,
		PrincipalGroup: "00000000-0000-7000-8000-0000000e5be1",
		ResourceGroup:  "00000000-0000-7000-8000-0000000e5be2",
		LocalAccounts:  []string{"root"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "run-as-root")
}

// TestTwoRulesCannotShareAName: a decision log naming the rule that produced it
// is the feature the whole decision point exists to provide, and two rules
// answering to one name makes it useless at exactly the moment it is read.
func TestTwoRulesCannotShareAName(t *testing.T) {
	_, err := policy.Add(shipped(t), policy.Rule{
		ID: "staff-web-access", Kind: policy.KindWebAccess,
		PrincipalGroup: policy.Everyone,
		ResourceGroup:  "00000000-0000-7000-8000-0000000e5be0",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "already there")
}

// TestARuleWithNoResourceIsRefused.
//
// Not by rendering an empty constraint, which is Cedar for "everything". A form
// left half-filled must not mean the broadest possible grant.
func TestARuleWithNoResourceIsRefused(t *testing.T) {
	_, err := policy.Render(policy.Rule{
		ID: "incomplete", Kind: policy.KindWebAccess, PrincipalGroup: policy.Everyone,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs a resource")
}

// TestAddingSomethingThatWouldNotCompileIsRefusedBeforeItIsStored.
func TestAddingSomethingThatWouldNotCompileIsRefused(t *testing.T) {
	_, err := policy.Add("this is not cedar at all", policy.Rule{
		ID: "fine", Kind: policy.KindWebAccess,
		PrincipalGroup: policy.Everyone,
		ResourceGroup:  "00000000-0000-7000-8000-0000000e5be0",
	})
	require.Error(t, err)
}
