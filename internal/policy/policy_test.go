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
				"nothing permits AdministerDirectory to a non-member",
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

// TestDirectoryAdminsMayAdminister.
//
// The permit rule and the group it names live in three places — this constant,
// migration 0008, and policies/cardinal.cedar. This test is what stops them
// drifting apart: change the UUID in one and administration silently stops
// working for everyone, with no error anywhere.
func TestDirectoryAdminsMayAdminister(t *testing.T) {
	e := engine(t)
	resource := types.NewEntityUID(policy.TypeApplication, "cardinal")

	admins := []claims.Group{{
		ID:    uuid.MustParse(policy.AdminGroupID),
		Name:  "directory-admins",
		Depth: 1,
	}}

	t.Run("a member with fresh device-bound auth is permitted", func(t *testing.T) {
		decision := e.Evaluate(policy.Request{
			Subject: subject(subjectOpts{
				deviceBound: true, authAge: time.Second, groups: admins,
			}),
			Action:   policy.ActionAdministerData,
			Resource: resource,
		})

		require.True(t, decision.Allowed,
			"membership of directory-admins must grant AdministerDirectory")
		assert.Contains(t, decision.Reasons, "directory-admins-may-administer")
	})

	// Each of these clears the permit and is then refused by a forbid. In Cedar
	// a forbid always beats a permit, and these three cases are the whole
	// reason that ordering matters here.
	refusals := []struct {
		name    string
		opts    subjectOpts
		reason  string
		because string
	}{
		{
			name:    "stale authentication",
			opts:    subjectOpts{deviceBound: true, authAge: 10 * time.Minute, groups: admins},
			reason:  "admin-requires-fresh-device-bound-auth",
			because: "an admin's forgotten session is the easiest way to take over a directory",
		},
		{
			name:    "synced passkey",
			opts:    subjectOpts{deviceBound: false, authAge: time.Second, groups: admins},
			reason:  "admin-requires-fresh-device-bound-auth",
			because: "a synced passkey is only as strong as the cloud account holding it",
		},
	}

	for _, tc := range refusals {
		t.Run(tc.name+" is still refused", func(t *testing.T) {
			decision := e.Evaluate(policy.Request{
				Subject:  subject(tc.opts),
				Action:   policy.ActionAdministerData,
				Resource: resource,
			})

			require.False(t, decision.Allowed, tc.because)
			assert.True(t, decision.ExplicitlyDenied(),
				"a member is refused by a forbid, not by default-deny, and the log must show which")
			assert.Contains(t, decision.Reasons, tc.reason)
		})
	}
}

// TestAdminGroupIDMatchesTheShippedPolicy.
//
// Cheap insurance against the one-character edit that breaks administration
// everywhere with no error to follow.
func TestAdminGroupIDMatchesTheShippedPolicy(t *testing.T) {
	source, err := os.ReadFile("../../policies/cardinal.cedar")
	require.NoError(t, err)

	assert.Contains(t, string(source), policy.AdminGroupID,
		"policies/cardinal.cedar must reference policy.AdminGroupID; "+
			"if this fails, migration 0008 needs checking too")
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

// TestApplicationAccessShipsPermissive.
//
// Cedar is default-deny, so introducing AccessApplication without a permit
// would have refused every sign-in to every application the moment the check
// existed. An upgrade that locks everyone out of everything is not a safe
// default, whatever it is a safe default for — so the shipped set permits, and
// operators narrow it.
func TestApplicationAccessShipsPermissive(t *testing.T) {
	e := engine(t)

	decision := e.Evaluate(policy.Request{
		Subject:  subject(subjectOpts{deviceBound: true}),
		Action:   policy.ActionAccessApplication,
		Resource: types.NewEntityUID(policy.TypeApplication, "grafana"),
	})

	require.True(t, decision.Allowed,
		"the shipped policy must not lock every user out of every application")
	assert.Contains(t, decision.Reasons, "any-user-may-access-any-application")
}

// TestApplicationAccessCanBeNarrowed.
//
// The point of the feature: replacing the shipped rule with a group-scoped one
// must actually restrict access, and must name the application readably.
func TestApplicationAccessCanBeNarrowed(t *testing.T) {
	const narrowed = `
@id("grafana-is-for-engineering")
permit (
    principal in Cardinal::Group::"11111111-1111-7111-8111-111111111111",
    action == Cardinal::Action::"AccessApplication",
    resource == Cardinal::Application::"grafana"
);`

	e, err := policy.NewEngine([]byte(narrowed), 1)
	require.NoError(t, err)

	engineers := []claims.Group{{
		ID:    uuid.MustParse("11111111-1111-7111-8111-111111111111"),
		Name:  "engineering",
		Depth: 1,
	}}

	cases := []struct {
		name        string
		groups      []claims.Group
		application string
		allowed     bool
		because     string
	}{
		{
			name: "a member reaching the named application", groups: engineers,
			application: "grafana", allowed: true,
		},
		{
			name: "a non-member", groups: nil,
			application: "grafana", allowed: false,
			because: "membership is the whole point of narrowing it",
		},
		{
			name: "a member reaching a different application", groups: engineers,
			application: "payroll", allowed: false,
			because: "a rule naming one application must not grant every application",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := e.Evaluate(policy.Request{
				Subject:  subject(subjectOpts{deviceBound: true, groups: tc.groups}),
				Action:   policy.ActionAccessApplication,
				Resource: types.NewEntityUID(policy.TypeApplication, types.String(tc.application)),
			})
			assert.Equal(t, tc.allowed, decision.Allowed, tc.because)
		})
	}
}

// TestAdminTiersAreSeparate.
//
// The point of splitting administration: whoever onboards staff must not be
// able to register an OIDC client, because choosing a client's redirect URIs is
// enough to stand up a phishing surface inside the organisation's own identity
// provider. That is a different blast radius from adding someone to a group,
// and one group holding both made "give someone admin" all-or-nothing.
func TestAdminTiersAreSeparate(t *testing.T) {
	e := engine(t)
	resource := types.NewEntityUID(policy.TypeApplication, "cardinal")

	member := func(id string, name string) []claims.Group {
		return []claims.Group{{ID: uuid.MustParse(id), Name: name, Depth: 1}}
	}

	cases := []struct {
		name    string
		groups  []claims.Group
		action  types.EntityUID
		allowed bool
		because string
	}{
		{
			name: "directory-admins manage people", allowed: true,
			groups: member(policy.AdminGroupID, "directory-admins"),
			action: policy.ActionManageUsers,
		},
		{
			name: "directory-admins manage applications", allowed: true,
			groups: member(policy.AdminGroupID, "directory-admins"),
			action: policy.ActionManageApplications,
			because: "the broad tier stays the superset, so nobody loses access " +
				"when the narrow ones are introduced",
		},
		{
			name: "user-admins manage people", allowed: true,
			groups: member(policy.UserAdminGroupID, "user-admins"),
			action: policy.ActionManageUsers,
		},
		{
			name: "user-admins may NOT register applications", allowed: false,
			groups: member(policy.UserAdminGroupID, "user-admins"),
			action: policy.ActionManageApplications,
			because: "redirect URIs are a phishing surface; onboarding staff " +
				"does not imply the authority to create one",
		},
		{
			name: "security-admins manage applications", allowed: true,
			groups: member(policy.SecurityAdminGroupID, "security-admins"),
			action: policy.ActionManageApplications,
		},
		{
			name: "security-admins may NOT disable accounts", allowed: false,
			groups:  member(policy.SecurityAdminGroupID, "security-admins"),
			action:  policy.ActionManageUsers,
			because: "registering clients does not imply authority over people",
		},
		{
			name: "user-admins are not directory-admins", allowed: false,
			groups: member(policy.UserAdminGroupID, "user-admins"),
			action: policy.ActionAdministerData,
			because: "the broad action must not be reachable through a narrow " +
				"tier, or the split buys nothing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := e.Evaluate(policy.Request{
				Subject: subject(subjectOpts{
					deviceBound: true, authAge: time.Second, groups: tc.groups,
				}),
				Action:   tc.action,
				Resource: resource,
			})
			assert.Equal(t, tc.allowed, decision.Allowed, tc.because)
		})
	}
}

// TestStepUpCoversEveryAdminAction.
//
// A narrow tier that escaped the freshness rule would be a way to administer
// *something* from a twelve-hour session, which is the hole the rule exists to
// close. Listed explicitly in policy rather than inferred, and asserted here so
// adding an action without adding it to the forbid fails loudly.
func TestStepUpCoversEveryAdminAction(t *testing.T) {
	e := engine(t)

	adminActions := map[string]types.EntityUID{
		"AdministerDirectory": policy.ActionAdministerData,
		"ManageUsers":         policy.ActionManageUsers,
		"ManageApplications":  policy.ActionManageApplications,
	}

	for name, action := range adminActions {
		t.Run(name+" needs a fresh device-bound credential", func(t *testing.T) {
			for _, tc := range []struct {
				what string
				opts subjectOpts
			}{
				{"a stale session", subjectOpts{deviceBound: true, authAge: 10 * time.Minute}},
				{"a synced passkey", subjectOpts{deviceBound: false, authAge: time.Second}},
			} {
				// Granted every tier, so only the forbid can refuse them.
				opts := tc.opts
				opts.groups = []claims.Group{
					{ID: uuid.MustParse(policy.AdminGroupID), Name: "directory-admins", Depth: 1},
				}

				decision := e.Evaluate(policy.Request{
					Subject:  subject(opts),
					Action:   action,
					Resource: types.NewEntityUID(policy.TypeApplication, "cardinal"),
				})

				require.False(t, decision.Allowed, "%s must not administer with %s", name, tc.what)
				assert.Contains(t, decision.Reasons, "admin-requires-fresh-device-bound-auth",
					"the refusal must name the step-up rule, not be default-deny")
			}
		})
	}
}

// TestBuiltInGroupIDsMatchTheShippedPolicy.
//
// Three copies of each identifier — this constant, the migration, and the
// policy file. Cheap insurance against the one-character edit that silently
// removes a tier's authority with no error anywhere.
func TestBuiltInGroupIDsMatchTheShippedPolicy(t *testing.T) {
	source, err := os.ReadFile("../../policies/cardinal.cedar")
	require.NoError(t, err)

	for name, id := range map[string]string{
		"directory-admins": policy.AdminGroupID,
		"user-admins":      policy.UserAdminGroupID,
		"security-admins":  policy.SecurityAdminGroupID,
	} {
		assert.Contains(t, string(source), id,
			"policies/cardinal.cedar must reference %s (%s); if this fails, "+
				"the migration needs checking too", name, id)
	}
}

// TestUngovernedActionsCatchesAnUpgradeGap.
//
// The failure it exists to prevent: Cardinal gains an action, a deployment
// keeps running its existing policy set, and an administrator is told they are
// not a member of a group they are a member of. Cedar is default-deny, so the
// refusal is correct and looks exactly like a bug.
func TestUngovernedActionsCatchesAnUpgradeGap(t *testing.T) {
	t.Run("the shipped set governs everything Cardinal evaluates", func(t *testing.T) {
		e := engine(t)
		assert.Empty(t, e.UngovernedActions(),
			"every action Cardinal can evaluate must appear in the default policy "+
				"set, or a fresh install refuses it for everyone")
	})

	t.Run("an older set is reported", func(t *testing.T) {
		// A policy set from before the tiers existed.
		const old = `
@id("directory-admins-may-administer")
permit (
    principal,
    action == Cardinal::Action::"AdministerDirectory",
    resource
);`
		e, err := policy.NewEngine([]byte(old), 1)
		require.NoError(t, err)

		missing := e.UngovernedActions()
		assert.Contains(t, missing, "ManageUsers")
		assert.Contains(t, missing, "ManageApplications")
		assert.NotContains(t, missing, "AdministerDirectory")
	})
}
