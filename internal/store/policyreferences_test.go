package store_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/policies"
)

// TestTheShippedPolicyNamesNothingAFreshInstallLacks.
//
// The regression test for the finding, run against a real migrated database
// rather than a list of constants: every group policies/cardinal.cedar names
// must exist the moment migrations finish.
//
// Three of the eleven shipped rules failed this for an entire release — the
// rules governing SSH, sudo and web access, all of them naming groups no
// migration created. Cedar is default-deny, so they refused everyone and looked
// like policy working.
func TestTheShippedPolicyNamesNothingAFreshInstallLacks(t *testing.T) {
	s := freshInstall(t)

	engine, err := policy.NewEngine(policies.Default, 1)
	require.NoError(t, err)

	dangling, err := engine.Dangling(t.Context(), s.PolicyReferenceExists)
	require.NoError(t, err)

	assert.Empty(t, dangling,
		"a freshly migrated database is missing something the default policy "+
			"set names:\n%s", policy.ExplainDangling(dangling))
}

// TestPolicyReferenceExistsMatchesOnTheRightColumn.
//
// Groups are named by UUID and applications by name, matching what each
// decision point puts in the request. Pairing those wrongly would report every
// reference as missing, and a warning that is always wrong is one everybody
// learns to skip.
func TestPolicyReferenceExistsMatchesOnTheRightColumn(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	group := mustCreate(t, s, directory.TypeGroup, "engineering")
	mustCreate(t, s, directory.TypeApplication, "grafana")

	found, err := s.PolicyReferenceExists(ctx, "group", group.ID.String())
	require.NoError(t, err)
	assert.True(t, found)

	found, err = s.PolicyReferenceExists(ctx, "application", "grafana")
	require.NoError(t, err)
	assert.True(t, found)

	// A group named by its *name* is reported absent even though a group by
	// that name exists, and that is the useful answer. Decision points build
	// group identifiers from the entity's id, so `Cardinal::Group::"engineering"`
	// matches nothing whatever the directory holds — a rule that looks obviously
	// right and never fires. Answering "found" here would hide exactly that.
	found, err = s.PolicyReferenceExists(ctx, "group", "engineering")
	require.NoError(t, err)
	assert.False(t, found,
		"a group named by name cannot match, so it must not be reported as present")

	found, err = s.PolicyReferenceExists(ctx, "group", uuid.New().String())
	require.NoError(t, err)
	assert.False(t, found)

	_, err = s.PolicyReferenceExists(ctx, "teapot", "anything")
	require.Error(t, err, "an unknown entity type is a bug in the caller, not an absence")
}
