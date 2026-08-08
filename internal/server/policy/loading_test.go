package policy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.londer.be/cardinal/internal/server/policy"
)

// TestUnnamedPolicyRejected guards the explainability the decision point exists
// to provide.
//
// cedar-go identifies policies positionally — policy0, policy1 — so without an
// @id annotation a decision log records "denied by policy2". That is useless to
// the person asking why, and the numbering shifts the moment someone inserts a
// policy above it, silently changing what historical decisions appear to
// reference.
//
// Rejected at load time rather than trusted to review, because the cost of
// forgetting is paid later and by someone else.
func TestUnnamedPolicyRejected(t *testing.T) {
	_, err := policy.NewEngine([]byte(`permit (principal, action, resource);`), 1)

	require.Error(t, err, "a policy with no @id annotation must not load")
	assert.Contains(t, err.Error(), "@id annotation")
	// The message names the offending policy and its line, so the fix is
	// obvious without hunting for it.
	assert.Contains(t, err.Error(), "line 1")
}

func TestNamedPolicyAccepted(t *testing.T) {
	engine, err := policy.NewEngine([]byte(
		`@id("test-policy")
		 permit (principal, action, resource);`), 1)

	require.NoError(t, err)
	assert.Equal(t, []string{"test-policy"}, engine.PolicyIDs())
}

// TestSourceReturnsTheRuleThatFired: the decision explorer shows the actual
// policy text, not merely its name. "Denied by break-glass-cannot-administer"
// beats "denied"; showing the rule is what lets someone judge whether the rule
// is right.
func TestSourceReturnsTheRuleThatFired(t *testing.T) {
	engine, err := policy.NewEngine([]byte(
		`@id("visible-policy")
		 permit (principal, action, resource);`), 1)
	require.NoError(t, err)

	source, ok := engine.Source("visible-policy")
	require.True(t, ok)
	assert.True(t, strings.Contains(source, "permit"),
		"the explorer needs the rule text, got: %q", source)

	_, ok = engine.Source("no-such-policy")
	assert.False(t, ok)
}

// TestMalformedPolicyRejected: a syntax error must stop the load, not silently
// produce a smaller policy set. A policy set missing its forbid rules would
// fail open.
func TestMalformedPolicyRejected(t *testing.T) {
	_, err := policy.NewEngine([]byte(`@id("broken") permit (this is not cedar`), 1)
	require.Error(t, err)
}
