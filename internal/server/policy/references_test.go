package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/server/policy"
)

// knows answers for a fixed set and denies everything else.
func knows(identifiers ...string) policy.Exists {
	present := map[string]bool{}
	for _, id := range identifiers {
		present[id] = true
	}
	return func(_ context.Context, _, identifier string) (bool, error) {
		return present[identifier], nil
	}
}

// TestReferencesIgnoresComments is the reason this reads rendered Cedar rather
// than the file.
//
// policies/cardinal.cedar documents how to write a rule by showing one, inside a
// comment, naming a group that deliberately does not exist. A checker scanning
// the source text would report that example on every run — and a warning that is
// always wrong is a warning everybody learns to skip, which would leave the real
// case no more visible than it was with no check at all.
func TestReferencesIgnoresComments(t *testing.T) {
	const document = `
// An example for whoever edits this file:
//     permit (
//         principal in Cardinal::Group::"00000000-0000-7000-8000-00000000dead",
//         action == Cardinal::Action::"AccessURL",
//         resource
//     );
@id("real-rule")
permit (
    principal in Cardinal::Group::"00000000-0000-7000-8000-00000000beef",
    action == Cardinal::Action::"AccessURL",
    resource
);`

	e, err := policy.NewEngine([]byte(document), 1)
	require.NoError(t, err)

	refs := e.References()
	require.Len(t, refs, 1, "only the rule counts, not the worked example beside it")
	assert.Equal(t, "00000000-0000-7000-8000-00000000beef", refs[0].Identifier)
	assert.Equal(t, "group", refs[0].Kind)
	assert.Equal(t, "real-rule", refs[0].Policy,
		"the report has to say which rule, or fixing it means reading the whole file")
}

// TestReferencesNamesActionsNever: actions are this package's own vocabulary,
// not directory data, and asking the database whether Cardinal::Action::"SSHLogin"
// exists would report every policy set as broken.
func TestReferencesNamesActionsNever(t *testing.T) {
	e := engine(t)
	for _, ref := range e.References() {
		assert.NotEqual(t, "action", ref.Kind)
	}
}

// TestDanglingFindsTheRuleThatCannotMatch.
//
// The failure being caught, stated plainly: a permit naming a group nobody
// created is refused by default-deny, which is indistinguishable from the rule
// working correctly and deciding the person does not qualify.
func TestDanglingFindsTheRuleThatCannotMatch(t *testing.T) {
	const document = `
@id("sre-may-log-into-production")
permit (
    principal in Cardinal::Group::"00000000-0000-7000-8000-00000000real",
    action == Cardinal::Action::"SSHLogin",
    resource in Cardinal::Group::"00000000-0000-7000-8000-0000000gone"
);`

	e, err := policy.NewEngine([]byte(document), 1)
	require.NoError(t, err)

	dangling, err := e.Dangling(t.Context(), knows("00000000-0000-7000-8000-00000000real"))
	require.NoError(t, err)

	require.Len(t, dangling, 1)
	assert.Equal(t, "00000000-0000-7000-8000-0000000gone", dangling[0].Identifier)
	assert.Equal(t, "sre-may-log-into-production", dangling[0].Policy)

	// The explanation carries the consequence, not just the name. "group X not
	// found" invites a shrug; "this rule never matches, which looks like it
	// working" does not.
	explanation := policy.ExplainDangling(dangling)
	assert.Contains(t, explanation, "sre-may-log-into-production")
	assert.Contains(t, explanation, "default-deny")
}

// TestDanglingAsksOncePerEntity: the shipped set names env-dev twice, and a
// report listing the same missing group twice teaches people to skim it.
func TestDanglingAsksOncePerEntity(t *testing.T) {
	const document = `
@id("a")
permit (principal, action == Cardinal::Action::"SSHLogin",
        resource in Cardinal::Group::"00000000-0000-7000-8000-00000000same");
@id("b")
permit (principal, action == Cardinal::Action::"RunAsRoot",
        resource in Cardinal::Group::"00000000-0000-7000-8000-00000000same");`

	e, err := policy.NewEngine([]byte(document), 1)
	require.NoError(t, err)

	asked := 0
	_, err = e.Dangling(t.Context(), func(context.Context, string, string) (bool, error) {
		asked++
		return false, nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, asked)
}

// TestDanglingSurfacesLookupFailure: a database that cannot answer must not
// read as "nothing is missing". That would be the check failing open, which is
// the exact shape of bug it exists to find.
func TestDanglingSurfacesLookupFailure(t *testing.T) {
	e := engine(t)

	_, err := e.Dangling(t.Context(), func(context.Context, string, string) (bool, error) {
		return false, errors.New("connection refused")
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
}

// TestShippedPolicyNamesOnlyGroupsAMigrationCreates is the regression test for
// the whole affair.
//
// Every group the default policy set names is answered for here by the constants
// in this package, which TestBuiltInGroupIDsMatchTheShippedPolicy separately
// pins to a migration. So this failing means the shipped set has grown a
// reference to something no fresh install will have — which is how three of its
// eleven rules came to be dead on arrival.
func TestShippedPolicyNamesOnlyGroupsAMigrationCreates(t *testing.T) {
	dangling, err := engine(t).Dangling(t.Context(), knows(
		policy.AdminGroupID,
		policy.UserAdminGroupID,
		policy.SecurityAdminGroupID,
		policy.StaffAppsGroupID,
		policy.SREGroupID,
		policy.ProdHostsGroupID,
		policy.EngineersGroupID,
		policy.DevHostsGroupID,
		policy.PlatformAdminsGroupID,
		policy.ProvisionersGroupID,
	))
	require.NoError(t, err)

	assert.Empty(t, dangling,
		"policies/cardinal.cedar names something a fresh install will not have: %s",
		policy.ExplainDangling(dangling))
}
