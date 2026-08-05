package policy_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/claims"
	"github.com/arthur-lonfils/cardinal/internal/policy"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// engine loads the real shipped policy set, not a test fixture.
//
// Testing a fixture would prove the engine works while saying nothing about
// whether the policies we actually deploy do what we believe. These are tests
// of the policy set as much as of the code.
func engine(t *testing.T) *policy.Engine {
	t.Helper()
	document, err := os.ReadFile(filepath.Join("..", "..", "policies", "cardinal.cedar"))
	require.NoError(t, err)

	e, err := policy.NewEngine(document, 1)
	require.NoError(t, err)
	return e
}

type subjectOpts struct {
	deviceBound bool
	emergency   bool
	authAge     time.Duration
	groups      []claims.Group
}

func subject(opts subjectOpts) *claims.Subject {
	return &claims.Subject{
		ID:     uuid.New(),
		Login:  "alonfils",
		Groups: opts.groups,
		Auth: claims.AuthContext{
			Method:      "passkey",
			At:          time.Now().Add(-opts.authAge),
			DeviceBound: opts.deviceBound,
			Emergency:   opts.emergency,
		},
	}
}

func TestPolicySetParses(t *testing.T) {
	e := engine(t)
	ids := e.PolicyIDs()
	assert.NotEmpty(t, ids)
	// Named policies, not positional ones: a decision log saying "denied by
	// policy 3" is useless six months later.
	for _, id := range ids {
		assert.NotRegexp(t, `^policy\d+$`, id,
			"every policy needs an @id annotation so decisions can name it")
	}
}

// TestDefaultDeny is the property everything else rests on.
func TestDefaultDeny(t *testing.T) {
	e := engine(t)

	decision := e.Evaluate(policy.Request{
		Subject:  subject(subjectOpts{deviceBound: true}),
		Action:   policy.ActionAccessURL,
		Resource: types.NewEntityUID(policy.TypeApplication, "unknown-app"),
	})

	assert.False(t, decision.Allowed, "an unmatched request must be denied")
	assert.False(t, decision.ExplicitlyDenied(),
		"nothing matched, so this is default-deny rather than an explicit forbid")
	assert.Contains(t, decision.Explain(), "no policy grants")
}

// TestAdminRequiresFreshDeviceBoundAuth covers step-up, which is the reason
// AuthContext is carried into policy at all.
func TestAdminRequiresFreshDeviceBoundAuth(t *testing.T) {
	e := engine(t)
	resource := types.NewEntityUID(policy.TypeApplication, "directory")

	cases := []struct {
		name    string
		opts    subjectOpts
		allowed bool
		because string
	}{
		{
			name:    "synced passkey is refused",
			opts:    subjectOpts{deviceBound: false, authAge: time.Second},
			allowed: false,
			because: "a synced passkey lives in a cloud account and is not hardware-bound",
		},
		{
			name:    "stale session is refused",
			opts:    subjectOpts{deviceBound: true, authAge: 10 * time.Minute},
			allowed: false,
			because: "a session left open on an unlocked laptop must not administer the directory",
		},
		{
			name:    "fresh device-bound auth still needs a permit",
			opts:    subjectOpts{deviceBound: true, authAge: time.Second},
			allowed: false,
			because: "clearing the forbid is not the same as being granted; " +
				"nothing in the default set permits AdministerDirectory",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := e.Evaluate(policy.Request{
				Subject:  subject(tc.opts),
				Action:   policy.ActionAdministerData,
				Resource: resource,
			})
			assert.Equal(t, tc.allowed, decision.Allowed, tc.because)
		})
	}
}

// TestBreakGlassCannotAdminister.
//
// Someone holding the offline key can already assume any account. Letting that
// session also rewrite the directory would make a stolen key catastrophic
// rather than merely serious, and changes made during an incident are the least
// likely to be reviewed.
func TestBreakGlassCannotAdminister(t *testing.T) {
	e := engine(t)

	decision := e.Evaluate(policy.Request{
		// Fresh and device-bound — every other requirement satisfied.
		Subject: subject(subjectOpts{
			deviceBound: true, emergency: true, authAge: time.Second,
		}),
		Action:   policy.ActionAdministerData,
		Resource: types.NewEntityUID(policy.TypeApplication, "directory"),
	})

	require.False(t, decision.Allowed)
	assert.True(t, decision.ExplicitlyDenied(),
		"this must be an explicit forbid, so the decision log shows the emergency rule fired")
	assert.Contains(t, decision.Reasons, "break-glass-cannot-administer")
}

func TestBreakGlassCannotReachProductionSSH(t *testing.T) {
	e := engine(t)

	decision := e.Evaluate(policy.Request{
		Subject:  subject(subjectOpts{deviceBound: true, emergency: true}),
		Action:   policy.ActionSSHLogin,
		Resource: types.NewEntityUID(policy.TypeHost, "web-01.prod"),
	})

	require.False(t, decision.Allowed)
	assert.Contains(t, decision.Reasons, "break-glass-no-production-ssh",
		"the emergency is in Cardinal, not necessarily in the fleet")
}

func TestSSHRequiresDeviceBoundCredential(t *testing.T) {
	e := engine(t)

	decision := e.Evaluate(policy.Request{
		Subject:  subject(subjectOpts{deviceBound: false}),
		Action:   policy.ActionSSHLogin,
		Resource: types.NewEntityUID(policy.TypeHost, "web-01.prod"),
	})

	require.False(t, decision.Allowed)
	assert.Contains(t, decision.Reasons, "ssh-requires-device-bound")
}

// TestRootRequiresRecentAuth: sudo happens mid-task, so the window is fifteen
// minutes rather than five. A window too short to work with gets removed
// entirely, which is worse than a slightly generous one.
func TestRootRequiresRecentAuth(t *testing.T) {
	e := engine(t)
	resource := types.NewEntityUID(policy.TypeHost, "web-01.prod")

	stale := e.Evaluate(policy.Request{
		Subject:  subject(subjectOpts{deviceBound: true, authAge: 20 * time.Minute}),
		Action:   policy.ActionRunAsRoot,
		Resource: resource,
	})
	require.False(t, stale.Allowed)
	assert.Contains(t, stale.Reasons, "root-requires-recent-auth")

	fresh := e.Evaluate(policy.Request{
		Subject:  subject(subjectOpts{deviceBound: true, authAge: time.Minute}),
		Action:   policy.ActionRunAsRoot,
		Resource: resource,
	})
	// Still denied — no permit exists — but for a different reason, and the
	// distinction is exactly what the decision explorer surfaces.
	assert.NotContains(t, fresh.Reasons, "root-requires-recent-auth",
		"a recent authentication must clear the freshness forbid")
}

// TestStaffWebAccessGranted confirms a permit actually works, so the suite is
// not merely proving that everything is denied.
func TestStaffWebAccessGranted(t *testing.T) {
	e := engine(t)

	decision := e.Evaluate(policy.Request{
		Subject:  subject(subjectOpts{deviceBound: true}),
		Action:   policy.ActionAccessURL,
		Resource: types.NewEntityUID(policy.TypeApplication, "grafana"),
		Context: map[string]types.Value{
			"audience": types.String("staff"),
		},
	})

	require.True(t, decision.Allowed, decision.Explain())
	assert.Contains(t, decision.Reasons, "staff-web-access")
}

// TestNoEvaluationErrors: a policy that fails to evaluate never grants access,
// but it is a defect. Swallowing it would let a broken policy masquerade as a
// working deny.
func TestNoEvaluationErrors(t *testing.T) {
	e := engine(t)

	for _, action := range []types.EntityUID{
		policy.ActionAccessURL,
		policy.ActionSSHLogin,
		policy.ActionRunAsRoot,
		policy.ActionAdministerData,
	} {
		decision := e.Evaluate(policy.Request{
			Subject:  subject(subjectOpts{deviceBound: true}),
			Action:   action,
			Resource: types.NewEntityUID(policy.TypeApplication, "anything"),
		})
		assert.Empty(t, decision.Errors,
			"policies must evaluate cleanly against a minimal subject; "+
				"an error here means a policy references an attribute that may be absent")
	}
}

// TestInheritedGroupMembership: policy authors write `principal in Group::"…"`
// without thinking about nesting, because the claims layer resolved the
// transitive closure — with expiry already applied.
func TestInheritedGroupMembership(t *testing.T) {
	e := engine(t)
	groupID := uuid.New()

	document := []byte(`
		@id("nested-group-access")
		permit (
		    principal in Cardinal::Group::"` + groupID.String() + `",
		    action == Cardinal::Action::"AccessURL",
		    resource
		);`)
	nested, err := policy.NewEngine(document, 1)
	require.NoError(t, err)

	// Depth 2: inherited through another group, not direct.
	decision := nested.Evaluate(policy.Request{
		Subject: subject(subjectOpts{
			groups: []claims.Group{{ID: groupID, Name: "prod-access", Depth: 2}},
		}),
		Action:   policy.ActionAccessURL,
		Resource: types.NewEntityUID(policy.TypeApplication, "grafana"),
	})

	assert.True(t, decision.Allowed,
		"inherited membership must satisfy `in`, or every policy author has to "+
			"enumerate nesting by hand")
	_ = e
}
